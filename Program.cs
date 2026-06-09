using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

const long MaxUploadBytes = 50L * 1024 * 1024;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

var storagePaths = BuildStoragePaths(app.Environment.ContentRootPath);
EnsureStorageDirectoriesExist(storagePaths);
var databaseConnectionString = BuildDatabaseConnectionString(storagePaths.DatabaseFilePath);

InitializeDatabase(databaseConnectionString);

ConfigureStaticFilePipeline(app);
MapHealthEndpoint(app);
MapAuthenticationEndpoints(app, databaseConnectionString);
MapFileEndpoints(app, databaseConnectionString, storagePaths.UploadsDirectoryPath, MaxUploadBytes);

app.Run();

static StoragePaths BuildStoragePaths(string contentRootPath)
{
    var storageDirectoryPath = Path.Combine(contentRootPath, "storage");
    var uploadsDirectoryPath = Path.Combine(storageDirectoryPath, "uploads");
    var databaseFilePath = Path.Combine(storageDirectoryPath, "fileshare.db");
    return new StoragePaths(storageDirectoryPath, uploadsDirectoryPath, databaseFilePath);
}

static void EnsureStorageDirectoriesExist(StoragePaths storagePaths)
{
    Directory.CreateDirectory(storagePaths.StorageDirectoryPath);
    Directory.CreateDirectory(storagePaths.UploadsDirectoryPath);
}

static string BuildDatabaseConnectionString(string databaseFilePath)
{
    return new SqliteConnectionStringBuilder
    {
        DataSource = databaseFilePath
    }.ToString();
}

void ConfigureStaticFilePipeline(WebApplication app)
{
    app.UseDefaultFiles();
    app.UseStaticFiles();
}

void MapHealthEndpoint(WebApplication app)
{
    app.MapGet("/api/health", HandleHealthCheck);
}

static IResult HandleHealthCheck()
{
    return Results.Ok(new
    {
        service = "FileShareExpert",
        status = "running"
    });
}

void MapAuthenticationEndpoints(WebApplication app, string connectionString)
{
    app.MapPost("/api/auth/register", (AuthRequest request) => HandleUserRegistrationAsync(request, connectionString));
    app.MapPost("/api/auth/login", (AuthRequest request, HttpRequest httpRequest, HttpResponse httpResponse) =>
        HandleUserLoginAsync(request, httpRequest, httpResponse, connectionString));
    app.MapGet("/api/auth/me", (HttpRequest httpRequest) => HandleCurrentUserAsync(httpRequest, connectionString));
    app.MapPost("/api/auth/logout", (HttpRequest httpRequest, HttpResponse httpResponse) =>
        HandleUserLogoutAsync(httpRequest, httpResponse, connectionString));
}

void MapFileEndpoints(WebApplication app, string connectionString, string uploadsDirectoryPath, long maxUploadBytes)
{
    app.MapPost("/api/files/upload", (HttpRequest httpRequest) =>
        HandleFileUploadAsync(httpRequest, connectionString, uploadsDirectoryPath, maxUploadBytes));
    app.MapGet("/api/files", (HttpRequest httpRequest) => HandleListFilesAsync(httpRequest, connectionString));
    app.MapGet("/api/files/{id:long}/download", (long id, HttpRequest httpRequest) =>
        HandleOwnedFileDownloadAsync(id, httpRequest, connectionString, uploadsDirectoryPath));
    app.MapDelete("/api/files/{id:long}", (long id, HttpRequest httpRequest) =>
        HandleFileDeletionAsync(id, httpRequest, connectionString, uploadsDirectoryPath));
    app.MapPut("/api/files/{id:long}/rename", (long id, RenameRequest request, HttpRequest httpRequest) =>
        HandleFileRenameAsync(id, request, httpRequest, connectionString));

    app.MapPost("/api/files/{id:long}/share", (long id, HttpRequest httpRequest) =>
        HandleShareCreationAsync(id, httpRequest, connectionString));
    app.MapDelete("/api/files/{id:long}/share", (long id, HttpRequest httpRequest) =>
        HandleShareDisableAsync(id, httpRequest, connectionString));
    app.MapGet("/api/share/{token}", (string token, HttpRequest httpRequest) =>
        HandleSharedFileDownloadAsync(token, httpRequest, connectionString, uploadsDirectoryPath));

    app.MapPost("/api/files/{id:long}/whitelist", (long id, WhitelistRequest request, HttpRequest httpRequest) =>
        HandleWhitelistAddAsync(id, request, httpRequest, connectionString));
    app.MapDelete("/api/files/{id:long}/whitelist/{username}", (long id, string username, HttpRequest httpRequest) =>
        HandleWhitelistRemoveAsync(id, username, httpRequest, connectionString));
    app.MapGet("/api/files/{id:long}/whitelist", (long id, HttpRequest httpRequest) =>
        HandleWhitelistListAsync(id, httpRequest, connectionString));
}

static async Task<IResult> HandleUserRegistrationAsync(AuthRequest request, string connectionString)
{
    var validationError = ValidateRegistrationInput(request);
    if (validationError is not null)
    {
        return validationError;
    }

    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    var hashedPassword = HashPassword(request.Password);
    var createResult = await TryCreateUserAsync(connection, request.Username.Trim(), hashedPassword);
    return createResult
        ? Results.Ok(new { message = "Пользователь зарегистрирован." })
        : Results.Conflict(new { error = "Пользователь с таким именем уже существует." });
}

static IResult? ValidateRegistrationInput(AuthRequest request)
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest(new { error = "Имя пользователя и пароль обязательны." });
    }

    if (request.Username.Length < 3 || request.Password.Length < 4)
    {
        return Results.BadRequest(new { error = "Минимум 3 символа для логина и 4 для пароля." });
    }

    return null;
}

static async Task<bool> TryCreateUserAsync(SqliteConnection connection, string username, string passwordHash)
{
    var command = connection.CreateCommand();
    command.CommandText = """
                          INSERT INTO users (username, password_hash, created_at)
                          VALUES ($username, $passwordHash, $createdAt);
                          """;
    command.Parameters.AddWithValue("$username", username);
    command.Parameters.AddWithValue("$passwordHash", passwordHash);
    command.Parameters.AddWithValue("$createdAt", DateTime.UtcNow.ToString("O"));

    try
    {
        await command.ExecuteNonQueryAsync();
        return true;
    }
    catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
    {
        return false;
    }
}

static async Task<IResult> HandleUserLoginAsync(
    AuthRequest request,
    HttpRequest httpRequest,
    HttpResponse httpResponse,
    string connectionString)
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest(new { error = "Имя пользователя и пароль обязательны." });
    }

    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    var credentials = await GetUserCredentialsByUsernameAsync(connection, request.Username.Trim());
    if (credentials is null || !VerifyPassword(request.Password, credentials.PasswordHash))
    {
        return Results.Unauthorized();
    }

    await UpgradeLegacyPasswordHashIfNeededAsync(connection, credentials, request.Password);

    var sessionToken = GenerateToken();
    var csrfToken = GenerateToken();
    await InsertUserSessionAsync(connection, sessionToken, credentials.UserId, csrfToken, DateTime.UtcNow.AddDays(30));
    SetAuthenticationCookie(httpRequest, httpResponse, sessionToken);

    return Results.Ok(new
    {
        csrfToken,
        user = new { id = credentials.UserId, username = credentials.Username }
    });
}

static async Task<UserCredentials?> GetUserCredentialsByUsernameAsync(SqliteConnection connection, string username)
{
    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT id, username, password_hash
                          FROM users
                          WHERE username = $username
                          LIMIT 1;
                          """;
    command.Parameters.AddWithValue("$username", username);

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        return null;
    }

    return new UserCredentials(
        reader.GetInt64(0),
        reader.GetString(1),
        reader.GetString(2));
}

static async Task UpgradeLegacyPasswordHashIfNeededAsync(
    SqliteConnection connection,
    UserCredentials credentials,
    string plainTextPassword)
{
    if (!IsLegacySha256Hash(credentials.PasswordHash))
    {
        return;
    }

    var command = connection.CreateCommand();
    command.CommandText = """
                          UPDATE users
                          SET password_hash = $passwordHash
                          WHERE id = $userId;
                          """;
    command.Parameters.AddWithValue("$passwordHash", HashPassword(plainTextPassword));
    command.Parameters.AddWithValue("$userId", credentials.UserId);
    await command.ExecuteNonQueryAsync();
}

static async Task InsertUserSessionAsync(
    SqliteConnection connection,
    string sessionToken,
    long userId,
    string csrfToken,
    DateTime expiresAtUtc)
{
    var command = connection.CreateCommand();
    command.CommandText = """
                          INSERT INTO user_sessions (token, user_id, expires_at, csrf_token)
                          VALUES ($token, $userId, $expiresAt, $csrfToken);
                          """;
    command.Parameters.AddWithValue("$token", sessionToken);
    command.Parameters.AddWithValue("$userId", userId);
    command.Parameters.AddWithValue("$expiresAt", expiresAtUtc.ToString("O"));
    command.Parameters.AddWithValue("$csrfToken", csrfToken);
    await command.ExecuteNonQueryAsync();
}

static void SetAuthenticationCookie(HttpRequest httpRequest, HttpResponse httpResponse, string sessionToken)
{
    httpResponse.Cookies.Append("fs_token", sessionToken, new CookieOptions
    {
        Expires = DateTimeOffset.UtcNow.AddDays(30),
        HttpOnly = true,
        Secure = httpRequest.IsHttps,
        IsEssential = true,
        SameSite = SameSiteMode.Lax
    });
}

static async Task<IResult> HandleCurrentUserAsync(HttpRequest httpRequest, string connectionString)
{
    var session = await GetAuthenticatedSessionAsync(httpRequest, connectionString);
    if (session is null)
    {
        return Results.Unauthorized();
    }

    return Results.Ok(new
    {
        id = session.User.Id,
        username = session.User.Username,
        csrfToken = session.CsrfToken
    });
}

static async Task<IResult> HandleUserLogoutAsync(HttpRequest httpRequest, HttpResponse httpResponse, string connectionString)
{
    var session = await GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
    if (session is null)
    {
        return Results.Unauthorized();
    }

    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    await DeleteSessionByTokenAsync(connection, session.SessionToken);
    httpResponse.Cookies.Delete("fs_token");
    return Results.Ok(new { message = "Вы вышли из системы." });
}

static async Task DeleteSessionByTokenAsync(SqliteConnection connection, string sessionToken)
{
    var command = connection.CreateCommand();
    command.CommandText = "DELETE FROM user_sessions WHERE token = $token;";
    command.Parameters.AddWithValue("$token", sessionToken);
    await command.ExecuteNonQueryAsync();
}

static async Task<IResult> HandleFileUploadAsync(
    HttpRequest httpRequest,
    string connectionString,
    string uploadsDirectoryPath,
    long maxUploadBytes)
{
    var session = await GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
    if (session is null)
    {
        return Results.Unauthorized();
    }

    var validationError = ValidateUploadRequestContentType(httpRequest);
    if (validationError is not null)
    {
        return validationError;
    }

    var uploadFile = await ExtractUploadFileAsync(httpRequest);
    if (uploadFile is null)
    {
        return Results.BadRequest(new { error = "Файл не передан." });
    }

    var fileSizeError = ValidateUploadFileSize(uploadFile, maxUploadBytes);
    if (fileSizeError is not null)
    {
        return fileSizeError;
    }

    var fileStorageNames = BuildStoredFileNames(uploadFile.FileName);
    var temporaryFilePath = Path.Combine(uploadsDirectoryPath, fileStorageNames.TempStoredName);
    var finalFilePath = Path.Combine(uploadsDirectoryPath, fileStorageNames.StoredName);

    await SaveUploadedFileToTemporaryPathAsync(uploadFile, temporaryFilePath);

    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    using var transaction = connection.BeginTransaction();

    try
    {
        var newFileId = await InsertUploadedFileRecordAsync(
            connection,
            transaction,
            session.User.Id,
            uploadFile,
            fileStorageNames.StoredName);

        MoveTemporaryFileToFinalPath(temporaryFilePath, finalFilePath);
        transaction.Commit();

        return Results.Ok(new
        {
            message = "Файл загружен.",
            file = new
            {
                id = newFileId,
                name = uploadFile.FileName,
                size = uploadFile.Length
            }
        });
    }
    catch
    {
        transaction.Rollback();
        CleanupFailedUploadFiles(temporaryFilePath, finalFilePath);
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
}

static IResult? ValidateUploadRequestContentType(HttpRequest request)
{
    return request.HasFormContentType
        ? null
        : Results.BadRequest(new { error = "Ожидается multipart/form-data." });
}

static async Task<IFormFile?> ExtractUploadFileAsync(HttpRequest request)
{
    var form = await request.ReadFormAsync();
    return form.Files["file"] ?? form.Files.FirstOrDefault();
}

static IResult? ValidateUploadFileSize(IFormFile file, long maxUploadBytes)
{
    if (file.Length <= 0)
    {
        return Results.BadRequest(new { error = "Файл не передан." });
    }

    return file.Length <= maxUploadBytes
        ? null
        : Results.BadRequest(new { error = $"Размер файла не должен превышать {maxUploadBytes / (1024 * 1024)} MB." });
}

static StoredFileNames BuildStoredFileNames(string originalFileName)
{
    var extension = Path.GetExtension(originalFileName);
    var storedName = $"{Guid.NewGuid():N}{extension}";
    return new StoredFileNames(storedName, $"{storedName}.uploading");
}

static async Task SaveUploadedFileToTemporaryPathAsync(IFormFile file, string temporaryFilePath)
{
    await using var stream = File.Create(temporaryFilePath);
    await file.CopyToAsync(stream);
}

static async Task<long> InsertUploadedFileRecordAsync(
    SqliteConnection connection,
    SqliteTransaction transaction,
    long ownerId,
    IFormFile file,
    string storedFileName)
{
    var insertCommand = connection.CreateCommand();
    insertCommand.Transaction = transaction;
    insertCommand.CommandText = """
                                INSERT INTO files (owner_id, original_name, stored_name, size, content_type, created_at)
                                VALUES ($ownerId, $originalName, $storedName, $size, $contentType, $createdAt);
                                """;
    insertCommand.Parameters.AddWithValue("$ownerId", ownerId);
    insertCommand.Parameters.AddWithValue("$originalName", file.FileName);
    insertCommand.Parameters.AddWithValue("$storedName", storedFileName);
    insertCommand.Parameters.AddWithValue("$size", file.Length);
    insertCommand.Parameters.AddWithValue("$contentType", file.ContentType ?? "application/octet-stream");
    insertCommand.Parameters.AddWithValue("$createdAt", DateTime.UtcNow.ToString("O"));
    await insertCommand.ExecuteNonQueryAsync();

    var idCommand = connection.CreateCommand();
    idCommand.Transaction = transaction;
    idCommand.CommandText = "SELECT last_insert_rowid();";
    return (long)(await idCommand.ExecuteScalarAsync() ?? 0L);
}

static void MoveTemporaryFileToFinalPath(string temporaryFilePath, string finalFilePath)
{
    File.Move(temporaryFilePath, finalFilePath, overwrite: false);
}

static void CleanupFailedUploadFiles(string temporaryFilePath, string finalFilePath)
{
    TryDeleteFileIfExists(temporaryFilePath);
    TryDeleteFileIfExists(finalFilePath);
}

static async Task<IResult> HandleListFilesAsync(HttpRequest httpRequest, string connectionString)
{
    var session = await GetAuthenticatedSessionAsync(httpRequest, connectionString);
    if (session is null)
    {
        return Results.Unauthorized();
    }

    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    var files = await LoadUserFilesAsync(connection, session.User.Id, httpRequest);
    return Results.Ok(files);
}

static async Task<List<object>> LoadUserFilesAsync(SqliteConnection connection, long ownerId, HttpRequest request)
{
    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT id, original_name, size, content_type, created_at, share_token
                          FROM files
                          WHERE owner_id = $ownerId
                          ORDER BY created_at DESC;
                          """;
    command.Parameters.AddWithValue("$ownerId", ownerId);

    var files = new List<object>();
    await using var reader = await command.ExecuteReaderAsync();
    while (await reader.ReadAsync())
    {
        var shareToken = reader.IsDBNull(5) ? null : reader.GetString(5);
        files.Add(new
        {
            id = reader.GetInt64(0),
            name = reader.GetString(1),
            size = reader.GetInt64(2),
            contentType = reader.GetString(3),
            createdAt = reader.GetString(4),
            shareToken,
            shareUrl = BuildShareUrl(request, shareToken)
        });
    }

    return files;
}

static string? BuildShareUrl(HttpRequest request, string? shareToken)
{
    return string.IsNullOrWhiteSpace(shareToken)
        ? null
        : $"{request.Scheme}://{request.Host}/api/share/{shareToken}";
}

static async Task<IResult> HandleOwnedFileDownloadAsync(
    long fileId,
    HttpRequest httpRequest,
    string connectionString,
    string uploadsDirectoryPath)
{
    var session = await GetAuthenticatedSessionAsync(httpRequest, connectionString);
    if (session is null)
    {
        return Results.Unauthorized();
    }

    var fileInfo = await GetOwnedFileInfoAsync(connectionString, fileId, session.User.Id);
    if (fileInfo is null)
    {
        return Results.NotFound(new { error = "Файл не найден." });
    }

    var filePath = Path.Combine(uploadsDirectoryPath, fileInfo.StoredName);
    return BuildFileDownloadResult(filePath, fileInfo.ContentType, fileInfo.OriginalName);
}

static IResult BuildFileDownloadResult(string filePath, string contentType, string downloadName)
{
    if (!File.Exists(filePath))
    {
        return Results.NotFound(new { error = "Файл отсутствует на диске." });
    }

    var stream = File.OpenRead(filePath);
    return Results.File(stream, contentType, downloadName);
}

static async Task<IResult> HandleFileDeletionAsync(
    long fileId,
    HttpRequest httpRequest,
    string connectionString,
    string uploadsDirectoryPath)
{
    var session = await GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
    if (session is null)
    {
        return Results.Unauthorized();
    }

    var fileInfo = await GetOwnedFileInfoAsync(connectionString, fileId, session.User.Id);
    if (fileInfo is null)
    {
        return Results.NotFound(new { error = "Файл не найден." });
    }

    var currentFilePath = Path.Combine(uploadsDirectoryPath, fileInfo.StoredName);
    if (!File.Exists(currentFilePath))
    {
        return Results.NotFound(new { error = "Файл отсутствует на диске." });
    }

    var quarantinePath = BuildDeletionQuarantinePath(uploadsDirectoryPath, fileInfo.StoredName);
    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    using var transaction = connection.BeginTransaction();

    try
    {
        File.Move(currentFilePath, quarantinePath, overwrite: false);
        await DeleteFileDatabaseRecordsAsync(connection, transaction, fileId);
        transaction.Commit();
        TryDeleteFileIfExists(quarantinePath);
        return Results.Ok(new { message = "Файл удалён." });
    }
    catch
    {
        transaction.Rollback();
        RestoreFileFromQuarantineIfNeeded(quarantinePath, currentFilePath);
        return Results.StatusCode(StatusCodes.Status500InternalServerError);
    }
}

static string BuildDeletionQuarantinePath(string uploadsDirectoryPath, string storedFileName)
{
    return Path.Combine(uploadsDirectoryPath, $"{storedFileName}.deleting.{Guid.NewGuid():N}");
}

static async Task DeleteFileDatabaseRecordsAsync(SqliteConnection connection, SqliteTransaction transaction, long fileId)
{
    var deleteWhitelistCommand = connection.CreateCommand();
    deleteWhitelistCommand.Transaction = transaction;
    deleteWhitelistCommand.CommandText = "DELETE FROM file_whitelist WHERE file_id = $fileId;";
    deleteWhitelistCommand.Parameters.AddWithValue("$fileId", fileId);
    await deleteWhitelistCommand.ExecuteNonQueryAsync();

    var deleteFileCommand = connection.CreateCommand();
    deleteFileCommand.Transaction = transaction;
    deleteFileCommand.CommandText = "DELETE FROM files WHERE id = $fileId;";
    deleteFileCommand.Parameters.AddWithValue("$fileId", fileId);

    var affectedRows = await deleteFileCommand.ExecuteNonQueryAsync();
    if (affectedRows == 0)
    {
        throw new InvalidOperationException("File row was not deleted.");
    }
}

static void RestoreFileFromQuarantineIfNeeded(string quarantinePath, string originalPath)
{
    if (!File.Exists(quarantinePath) || File.Exists(originalPath))
    {
        return;
    }

    File.Move(quarantinePath, originalPath, overwrite: false);
}

static async Task<IResult> HandleFileRenameAsync(
    long fileId,
    RenameRequest request,
    HttpRequest httpRequest,
    string connectionString)
{
    var session = await GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
    if (session is null)
    {
        return Results.Unauthorized();
    }

    if (string.IsNullOrWhiteSpace(request.NewFileName))
    {
        return Results.BadRequest(new { error = "Новое имя файла пустое." });
    }

    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    var command = connection.CreateCommand();
    command.CommandText = """
                          UPDATE files
                          SET original_name = $newFileName
                          WHERE id = $fileId AND owner_id = $ownerId;
                          """;
    command.Parameters.AddWithValue("$newFileName", request.NewFileName.Trim());
    command.Parameters.AddWithValue("$fileId", fileId);
    command.Parameters.AddWithValue("$ownerId", session.User.Id);

    var updatedRows = await command.ExecuteNonQueryAsync();
    return updatedRows == 0
        ? Results.NotFound(new { error = "Файл не найден." })
        : Results.Ok(new { message = "Файл переименован." });
}

static async Task<IResult> HandleShareCreationAsync(long fileId, HttpRequest httpRequest, string connectionString)
{
    var session = await GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
    if (session is null)
    {
        return Results.Unauthorized();
    }

    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    var existingToken = await GetShareTokenForOwnedFileAsync(connection, fileId, session.User.Id);
    if (existingToken is null)
    {
        return Results.NotFound(new { error = "Файл не найден." });
    }

    if (string.IsNullOrWhiteSpace(existingToken))
    {
        existingToken = GenerateToken();
        await UpdateShareTokenForOwnedFileAsync(connection, fileId, session.User.Id, existingToken);
    }

    return Results.Ok(new
    {
        shareToken = existingToken,
        shareUrl = BuildShareUrl(httpRequest, existingToken)
    });
}

static async Task<string?> GetShareTokenForOwnedFileAsync(SqliteConnection connection, long fileId, long ownerId)
{
    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT share_token
                          FROM files
                          WHERE id = $fileId AND owner_id = $ownerId
                          LIMIT 1;
                          """;
    command.Parameters.AddWithValue("$fileId", fileId);
    command.Parameters.AddWithValue("$ownerId", ownerId);

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        return null;
    }

    return reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
}

static async Task UpdateShareTokenForOwnedFileAsync(SqliteConnection connection, long fileId, long ownerId, string shareToken)
{
    var command = connection.CreateCommand();
    command.CommandText = """
                          UPDATE files
                          SET share_token = $shareToken
                          WHERE id = $fileId AND owner_id = $ownerId;
                          """;
    command.Parameters.AddWithValue("$shareToken", shareToken);
    command.Parameters.AddWithValue("$fileId", fileId);
    command.Parameters.AddWithValue("$ownerId", ownerId);
    await command.ExecuteNonQueryAsync();
}

static async Task<IResult> HandleShareDisableAsync(long fileId, HttpRequest httpRequest, string connectionString)
{
    var session = await GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
    if (session is null)
    {
        return Results.Unauthorized();
    }

    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    var command = connection.CreateCommand();
    command.CommandText = """
                          UPDATE files
                          SET share_token = NULL
                          WHERE id = $fileId AND owner_id = $ownerId;
                          """;
    command.Parameters.AddWithValue("$fileId", fileId);
    command.Parameters.AddWithValue("$ownerId", session.User.Id);
    var updatedRows = await command.ExecuteNonQueryAsync();

    return updatedRows == 0
        ? Results.NotFound(new { error = "Файл не найден." })
        : Results.Ok(new { message = "Ссылка на файл отключена." });
}

static async Task<IResult> HandleSharedFileDownloadAsync(
    string shareToken,
    HttpRequest httpRequest,
    string connectionString,
    string uploadsDirectoryPath)
{
    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    var sharedFile = await GetSharedFileByTokenAsync(connection, shareToken);
    if (sharedFile is null)
    {
        return Results.NotFound(new { error = "Ссылка не найдена." });
    }

    var whitelistExists = await DoesWhitelistExistForFileAsync(connection, sharedFile.FileId);
    if (whitelistExists)
    {
        var session = await GetAuthenticatedSessionAsync(httpRequest, connectionString);
        if (session is null)
        {
            return Results.Unauthorized();
        }

        var userAllowed = session.User.Id == sharedFile.OwnerId ||
                          await IsUserInWhitelistAsync(connection, sharedFile.FileId, session.User.Id);
        if (!userAllowed)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
    }

    var sharedFilePath = Path.Combine(uploadsDirectoryPath, sharedFile.StoredName);
    return BuildFileDownloadResult(sharedFilePath, sharedFile.ContentType, sharedFile.OriginalName);
}

static async Task<SharedFileInfo?> GetSharedFileByTokenAsync(SqliteConnection connection, string shareToken)
{
    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT id, owner_id, original_name, stored_name, content_type
                          FROM files
                          WHERE share_token = $token
                          LIMIT 1;
                          """;
    command.Parameters.AddWithValue("$token", shareToken);

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        return null;
    }

    return new SharedFileInfo(
        reader.GetInt64(0),
        reader.GetInt64(1),
        reader.GetString(2),
        reader.GetString(3),
        reader.GetString(4));
}

static async Task<bool> DoesWhitelistExistForFileAsync(SqliteConnection connection, long fileId)
{
    var command = connection.CreateCommand();
    command.CommandText = "SELECT COUNT(1) FROM file_whitelist WHERE file_id = $fileId;";
    command.Parameters.AddWithValue("$fileId", fileId);
    return Convert.ToInt32(await command.ExecuteScalarAsync() ?? 0) > 0;
}

static async Task<bool> IsUserInWhitelistAsync(SqliteConnection connection, long fileId, long userId)
{
    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT COUNT(1)
                          FROM file_whitelist
                          WHERE file_id = $fileId AND user_id = $userId;
                          """;
    command.Parameters.AddWithValue("$fileId", fileId);
    command.Parameters.AddWithValue("$userId", userId);
    return Convert.ToInt32(await command.ExecuteScalarAsync() ?? 0) > 0;
}

static async Task<IResult> HandleWhitelistAddAsync(
    long fileId,
    WhitelistRequest request,
    HttpRequest httpRequest,
    string connectionString)
{
    var ownerSession = await GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
    if (ownerSession is null)
    {
        return Results.Unauthorized();
    }

    if (string.IsNullOrWhiteSpace(request.Username))
    {
        return Results.BadRequest(new { error = "Имя пользователя не указано." });
    }

    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    var ownerHasFile = await DoesOwnerHaveFileAsync(connection, fileId, ownerSession.User.Id);
    if (!ownerHasFile)
    {
        return Results.NotFound(new { error = "Файл не найден." });
    }

    var targetUserId = await GetUserIdByUsernameAsync(connection, request.Username.Trim());
    if (targetUserId is null)
    {
        return Results.NotFound(new { error = "Пользователь для белого списка не найден." });
    }

    await AddUserToWhitelistAsync(connection, fileId, targetUserId.Value);
    return Results.Ok(new { message = "Пользователь добавлен в белый список." });
}

static async Task<bool> DoesOwnerHaveFileAsync(SqliteConnection connection, long fileId, long ownerId)
{
    var command = connection.CreateCommand();
    command.CommandText = "SELECT COUNT(1) FROM files WHERE id = $fileId AND owner_id = $ownerId;";
    command.Parameters.AddWithValue("$fileId", fileId);
    command.Parameters.AddWithValue("$ownerId", ownerId);
    return Convert.ToInt32(await command.ExecuteScalarAsync() ?? 0) > 0;
}

static async Task<long?> GetUserIdByUsernameAsync(SqliteConnection connection, string username)
{
    var command = connection.CreateCommand();
    command.CommandText = "SELECT id FROM users WHERE username = $username LIMIT 1;";
    command.Parameters.AddWithValue("$username", username);
    var result = await command.ExecuteScalarAsync();
    return result is null ? null : (long)result;
}

static async Task AddUserToWhitelistAsync(SqliteConnection connection, long fileId, long userId)
{
    var command = connection.CreateCommand();
    command.CommandText = """
                          INSERT OR IGNORE INTO file_whitelist (file_id, user_id)
                          VALUES ($fileId, $userId);
                          """;
    command.Parameters.AddWithValue("$fileId", fileId);
    command.Parameters.AddWithValue("$userId", userId);
    await command.ExecuteNonQueryAsync();
}

static async Task<IResult> HandleWhitelistRemoveAsync(
    long fileId,
    string username,
    HttpRequest httpRequest,
    string connectionString)
{
    var ownerSession = await GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
    if (ownerSession is null)
    {
        return Results.Unauthorized();
    }

    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    var ownerHasFile = await DoesOwnerHaveFileAsync(connection, fileId, ownerSession.User.Id);
    if (!ownerHasFile)
    {
        return Results.NotFound(new { error = "Файл не найден." });
    }

    var targetUserId = await GetUserIdByUsernameAsync(connection, username.Trim());
    if (targetUserId is null)
    {
        return Results.NotFound(new { error = "Пользователь не найден." });
    }

    await RemoveUserFromWhitelistAsync(connection, fileId, targetUserId.Value);
    return Results.Ok(new { message = "Пользователь удалён из белого списка." });
}

static async Task RemoveUserFromWhitelistAsync(SqliteConnection connection, long fileId, long userId)
{
    var command = connection.CreateCommand();
    command.CommandText = """
                          DELETE FROM file_whitelist
                          WHERE file_id = $fileId AND user_id = $userId;
                          """;
    command.Parameters.AddWithValue("$fileId", fileId);
    command.Parameters.AddWithValue("$userId", userId);
    await command.ExecuteNonQueryAsync();
}

static async Task<IResult> HandleWhitelistListAsync(long fileId, HttpRequest httpRequest, string connectionString)
{
    var ownerSession = await GetAuthenticatedSessionAsync(httpRequest, connectionString);
    if (ownerSession is null)
    {
        return Results.Unauthorized();
    }

    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    var ownerHasFile = await DoesOwnerHaveFileAsync(connection, fileId, ownerSession.User.Id);
    if (!ownerHasFile)
    {
        return Results.NotFound(new { error = "Файл не найден." });
    }

    var usernames = await GetWhitelistUsernamesAsync(connection, fileId);
    return Results.Ok(usernames);
}

static async Task<List<string>> GetWhitelistUsernamesAsync(SqliteConnection connection, long fileId)
{
    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT u.username
                          FROM file_whitelist fw
                          INNER JOIN users u ON u.id = fw.user_id
                          WHERE fw.file_id = $fileId
                          ORDER BY u.username;
                          """;
    command.Parameters.AddWithValue("$fileId", fileId);

    var usernames = new List<string>();
    await using var reader = await command.ExecuteReaderAsync();
    while (await reader.ReadAsync())
    {
        usernames.Add(reader.GetString(0));
    }

    return usernames;
}

static void InitializeDatabase(string connectionString)
{
    using var connection = new SqliteConnection(connectionString);
    connection.Open();

    using var command = connection.CreateCommand();
    command.CommandText = """
                          CREATE TABLE IF NOT EXISTS users (
                              id INTEGER PRIMARY KEY AUTOINCREMENT,
                              username TEXT NOT NULL UNIQUE,
                              password_hash TEXT NOT NULL,
                              created_at TEXT NOT NULL
                          );

                          CREATE TABLE IF NOT EXISTS user_sessions (
                              token TEXT PRIMARY KEY,
                              user_id INTEGER NOT NULL,
                              expires_at TEXT NOT NULL,
                              csrf_token TEXT NOT NULL DEFAULT '',
                              FOREIGN KEY (user_id) REFERENCES users(id)
                          );

                          CREATE TABLE IF NOT EXISTS files (
                              id INTEGER PRIMARY KEY AUTOINCREMENT,
                              owner_id INTEGER NOT NULL,
                              original_name TEXT NOT NULL,
                              stored_name TEXT NOT NULL,
                              size INTEGER NOT NULL,
                              content_type TEXT NOT NULL,
                              created_at TEXT NOT NULL,
                              share_token TEXT UNIQUE,
                              FOREIGN KEY (owner_id) REFERENCES users(id)
                          );

                          CREATE TABLE IF NOT EXISTS file_whitelist (
                              file_id INTEGER NOT NULL,
                              user_id INTEGER NOT NULL,
                              PRIMARY KEY (file_id, user_id),
                              FOREIGN KEY (file_id) REFERENCES files(id),
                              FOREIGN KEY (user_id) REFERENCES users(id)
                          );
                          """;
    command.ExecuteNonQuery();

    EnsureUserSessionsCsrfColumnExists(connection);
}

static void EnsureUserSessionsCsrfColumnExists(SqliteConnection connection)
{
    using var command = connection.CreateCommand();
    command.CommandText = "PRAGMA table_info(user_sessions);";

    using var reader = command.ExecuteReader();
    while (reader.Read())
    {
        var existingColumnName = reader.GetString(1);
        if (string.Equals(existingColumnName, "csrf_token", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }
    }

    using var alterCommand = connection.CreateCommand();
    alterCommand.CommandText = "ALTER TABLE user_sessions ADD COLUMN csrf_token TEXT NOT NULL DEFAULT '';";
    alterCommand.ExecuteNonQuery();
}

static async Task<SessionInfo?> GetAuthenticatedSessionAsync(
    HttpRequest request,
    string connectionString,
    bool requireCsrf = false)
{
    var sessionToken = GetSessionTokenFromCookie(request);
    if (string.IsNullOrWhiteSpace(sessionToken))
    {
        return null;
    }

    var csrfTokenFromHeader = GetCsrfTokenFromHeader(request);
    if (requireCsrf && string.IsNullOrWhiteSpace(csrfTokenFromHeader))
    {
        return null;
    }

    await using var connection = await OpenSqliteConnectionAsync(connectionString);
    var session = await FindSessionByTokenAsync(connection, sessionToken);
    if (session is null)
    {
        return null;
    }

    var sessionWithCsrf = await EnsureSessionHasCsrfTokenAsync(connection, session);
    if (requireCsrf && !AreCsrfTokensEqual(sessionWithCsrf.CsrfToken, csrfTokenFromHeader))
    {
        return null;
    }

    return sessionWithCsrf;
}

static string GetSessionTokenFromCookie(HttpRequest request)
{
    return request.Cookies["fs_token"]?.Trim() ?? string.Empty;
}

static string GetCsrfTokenFromHeader(HttpRequest request)
{
    return request.Headers["X-CSRF-Token"].ToString().Trim();
}

static async Task<SessionInfo?> FindSessionByTokenAsync(SqliteConnection connection, string sessionToken)
{
    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT s.token, u.id, u.username, s.csrf_token
                          FROM user_sessions s
                          INNER JOIN users u ON u.id = s.user_id
                          WHERE s.token = $token
                            AND s.expires_at > $now
                          LIMIT 1;
                          """;
    command.Parameters.AddWithValue("$token", sessionToken);
    command.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("O"));

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        return null;
    }

    return new SessionInfo(
        reader.GetString(0),
        new UserInfo(reader.GetInt64(1), reader.GetString(2)),
        reader.IsDBNull(3) ? string.Empty : reader.GetString(3));
}

static async Task<SessionInfo> EnsureSessionHasCsrfTokenAsync(SqliteConnection connection, SessionInfo session)
{
    if (!string.IsNullOrWhiteSpace(session.CsrfToken))
    {
        return session;
    }

    var newCsrfToken = GenerateToken();
    var command = connection.CreateCommand();
    command.CommandText = """
                          UPDATE user_sessions
                          SET csrf_token = $csrfToken
                          WHERE token = $token;
                          """;
    command.Parameters.AddWithValue("$csrfToken", newCsrfToken);
    command.Parameters.AddWithValue("$token", session.SessionToken);
    await command.ExecuteNonQueryAsync();

    return session with { CsrfToken = newCsrfToken };
}

static bool AreCsrfTokensEqual(string expectedToken, string providedToken)
{
    if (string.IsNullOrWhiteSpace(expectedToken) || string.IsNullOrWhiteSpace(providedToken))
    {
        return false;
    }

    var expectedBytes = Encoding.UTF8.GetBytes(expectedToken);
    var providedBytes = Encoding.UTF8.GetBytes(providedToken);
    return expectedBytes.Length == providedBytes.Length &&
           CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes);
}

static async Task<FileInfoRow?> GetOwnedFileInfoAsync(string connectionString, long fileId, long ownerId)
{
    await using var connection = await OpenSqliteConnectionAsync(connectionString);

    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT id, owner_id, original_name, stored_name, content_type
                          FROM files
                          WHERE id = $fileId AND owner_id = $ownerId
                          LIMIT 1;
                          """;
    command.Parameters.AddWithValue("$fileId", fileId);
    command.Parameters.AddWithValue("$ownerId", ownerId);

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        return null;
    }

    return new FileInfoRow(
        reader.GetInt64(0),
        reader.GetInt64(1),
        reader.GetString(2),
        reader.GetString(3),
        reader.GetString(4));
}

static async Task<SqliteConnection> OpenSqliteConnectionAsync(string connectionString)
{
    var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();
    return connection;
}

static string HashPassword(string password)
{
    const int iterations = 120_000;
    var salt = RandomNumberGenerator.GetBytes(16);
    var hash = Rfc2898DeriveBytes.Pbkdf2(
        password,
        salt,
        iterations,
        HashAlgorithmName.SHA256,
        32);
    return $"PBKDF2${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
}

static bool VerifyPassword(string password, string storedHash)
{
    if (storedHash.StartsWith("PBKDF2$", StringComparison.Ordinal))
    {
        return VerifyPbkdf2Password(password, storedHash);
    }

    var legacyHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password)));
    return string.Equals(legacyHash, storedHash, StringComparison.Ordinal);
}

static bool VerifyPbkdf2Password(string password, string storedHash)
{
    var parts = storedHash.Split('$', StringSplitOptions.RemoveEmptyEntries);
    if (parts.Length != 4 || !int.TryParse(parts[1], out var iterations))
    {
        return false;
    }

    byte[] salt;
    byte[] expectedHash;
    try
    {
        salt = Convert.FromBase64String(parts[2]);
        expectedHash = Convert.FromBase64String(parts[3]);
    }
    catch
    {
        return false;
    }

    var providedHash = Rfc2898DeriveBytes.Pbkdf2(
        password,
        salt,
        iterations,
        HashAlgorithmName.SHA256,
        expectedHash.Length);
    return CryptographicOperations.FixedTimeEquals(providedHash, expectedHash);
}

static bool IsLegacySha256Hash(string storedHash)
{
    return !storedHash.StartsWith("PBKDF2$", StringComparison.Ordinal);
}

static string GenerateToken()
{
    Span<byte> bytes = stackalloc byte[32];
    RandomNumberGenerator.Fill(bytes);
    return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

static void TryDeleteFileIfExists(string path)
{
    if (File.Exists(path))
    {
        File.Delete(path);
    }
}

record StoragePaths(string StorageDirectoryPath, string UploadsDirectoryPath, string DatabaseFilePath);
record StoredFileNames(string StoredName, string TempStoredName);
record UserCredentials(long UserId, string Username, string PasswordHash);
record SharedFileInfo(long FileId, long OwnerId, string OriginalName, string StoredName, string ContentType);
record AuthRequest(string Username, string Password);
record RenameRequest(string NewFileName);
record WhitelistRequest(string Username);
record UserInfo(long Id, string Username);
record SessionInfo(string SessionToken, UserInfo User, string CsrfToken);
record FileInfoRow(long Id, long OwnerId, string OriginalName, string StoredName, string ContentType);

public partial class Program;
