using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

var storageRoot = Path.Combine(app.Environment.ContentRootPath, "storage");
var uploadsRoot = Path.Combine(storageRoot, "uploads");
Directory.CreateDirectory(storageRoot);
Directory.CreateDirectory(uploadsRoot);

var connectionString = new SqliteConnectionStringBuilder
{
    DataSource = Path.Combine(storageRoot, "fileshare.db")
}.ToString();

InitializeDatabase(connectionString);

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/health", () => Results.Ok(new
{
    service = "FileShareExpert",
    status = "running"
}));

app.MapPost("/api/auth/register", async (AuthRequest request) =>
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
    {
        return Results.BadRequest(new { error = "Имя пользователя и пароль обязательны." });
    }

    if (request.Username.Length < 3 || request.Password.Length < 4)
    {
        return Results.BadRequest(new { error = "Минимум 3 символа для логина и 4 для пароля." });
    }

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var insertCommand = connection.CreateCommand();
    insertCommand.CommandText = """
                                INSERT INTO users (username, password_hash, created_at)
                                VALUES ($username, $passwordHash, $createdAt);
                                """;
    insertCommand.Parameters.AddWithValue("$username", request.Username.Trim());
    insertCommand.Parameters.AddWithValue("$passwordHash", HashPassword(request.Password));
    insertCommand.Parameters.AddWithValue("$createdAt", DateTime.UtcNow.ToString("O"));

    try
    {
        await insertCommand.ExecuteNonQueryAsync();
    }
    catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
    {
        return Results.Conflict(new { error = "Пользователь с таким именем уже существует." });
    }

    return Results.Ok(new { message = "Пользователь зарегистрирован." });
});

app.MapPost("/api/auth/login", async (AuthRequest request, HttpResponse httpResponse) =>
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT id, username, password_hash
                          FROM users
                          WHERE username = $username
                          LIMIT 1;
                          """;
    command.Parameters.AddWithValue("$username", request.Username.Trim());

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        return Results.Unauthorized();
    }

    var userId = reader.GetInt64(0);
    var username = reader.GetString(1);
    var passwordHash = reader.GetString(2);

    if (!string.Equals(passwordHash, HashPassword(request.Password), StringComparison.Ordinal))
    {
        return Results.Unauthorized();
    }

    var token = GenerateToken();
    var expiresAt = DateTime.UtcNow.AddDays(30).ToString("O");

    var sessionCommand = connection.CreateCommand();
    sessionCommand.CommandText = """
                                 INSERT INTO user_sessions (token, user_id, expires_at)
                                 VALUES ($token, $userId, $expiresAt);
                                 """;
    sessionCommand.Parameters.AddWithValue("$token", token);
    sessionCommand.Parameters.AddWithValue("$userId", userId);
    sessionCommand.Parameters.AddWithValue("$expiresAt", expiresAt);
    await sessionCommand.ExecuteNonQueryAsync();

    httpResponse.Cookies.Append("fs_token", token, new CookieOptions
    {
        Expires = DateTimeOffset.UtcNow.AddDays(30),
        HttpOnly = false,
        IsEssential = true,
        SameSite = SameSiteMode.Lax
    });

    return Results.Ok(new
    {
        token,
        user = new { id = userId, username }
    });
});

app.MapGet("/api/auth/me", async (HttpRequest httpRequest) =>
{
    var user = await GetAuthenticatedUser(httpRequest, connectionString);
    return user is null
        ? Results.Unauthorized()
        : Results.Ok(new { user.Id, user.Username });
});

app.MapPost("/api/auth/logout", async (HttpRequest httpRequest, HttpResponse httpResponse) =>
{
    var tokenHeader = httpRequest.Headers.Authorization.ToString();
    var tokenFromHeader = tokenHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        ? tokenHeader["Bearer ".Length..].Trim()
        : string.Empty;
    var tokenFromCookie = httpRequest.Cookies["fs_token"]?.Trim() ?? string.Empty;
    var token = !string.IsNullOrWhiteSpace(tokenFromHeader) ? tokenFromHeader : tokenFromCookie;

    if (!string.IsNullOrWhiteSpace(token))
    {
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();
        var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM user_sessions WHERE token = $token;";
        command.Parameters.AddWithValue("$token", token);
        await command.ExecuteNonQueryAsync();
    }

    httpResponse.Cookies.Delete("fs_token");
    return Results.Ok(new { message = "Вы вышли из системы." });
});

app.MapPost("/api/files/upload", async (HttpRequest httpRequest) =>
{
    var user = await GetAuthenticatedUser(httpRequest, connectionString);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    if (!httpRequest.HasFormContentType)
    {
        return Results.BadRequest(new { error = "Ожидается multipart/form-data." });
    }

    var form = await httpRequest.ReadFormAsync();
    var file = form.Files["file"] ?? form.Files.FirstOrDefault();
    if (file is null || file.Length == 0)
    {
        return Results.BadRequest(new { error = "Файл не передан." });
    }

    var extension = Path.GetExtension(file.FileName);
    var storedName = $"{Guid.NewGuid():N}{extension}";
    var destinationPath = Path.Combine(uploadsRoot, storedName);

    await using (var stream = File.Create(destinationPath))
    {
        await file.CopyToAsync(stream);
    }

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    command.CommandText = """
                          INSERT INTO files (owner_id, original_name, stored_name, size, content_type, created_at)
                          VALUES ($ownerId, $originalName, $storedName, $size, $contentType, $createdAt);
                          """;
    command.Parameters.AddWithValue("$ownerId", user.Id);
    command.Parameters.AddWithValue("$originalName", file.FileName);
    command.Parameters.AddWithValue("$storedName", storedName);
    command.Parameters.AddWithValue("$size", file.Length);
    command.Parameters.AddWithValue("$contentType", file.ContentType ?? "application/octet-stream");
    command.Parameters.AddWithValue("$createdAt", DateTime.UtcNow.ToString("O"));

    await command.ExecuteNonQueryAsync();

    var idCommand = connection.CreateCommand();
    idCommand.CommandText = "SELECT last_insert_rowid();";
    var fileId = (long)(await idCommand.ExecuteScalarAsync() ?? 0L);

    return Results.Ok(new
    {
        message = "Файл загружен.",
        file = new
        {
            id = fileId,
            name = file.FileName,
            size = file.Length
        }
    });
});

app.MapGet("/api/files", async (HttpRequest httpRequest) =>
{
    var user = await GetAuthenticatedUser(httpRequest, connectionString);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT id, original_name, size, content_type, created_at, share_token
                          FROM files
                          WHERE owner_id = $ownerId
                          ORDER BY created_at DESC;
                          """;
    command.Parameters.AddWithValue("$ownerId", user.Id);

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
            shareUrl = shareToken is null ? null : $"{httpRequest.Scheme}://{httpRequest.Host}/api/share/{shareToken}"
        });
    }

    return Results.Ok(files);
});

app.MapGet("/api/files/{id:long}/download", async (long id, HttpRequest httpRequest) =>
{
    var user = await GetAuthenticatedUser(httpRequest, connectionString);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    var fileInfo = await GetFileOwnedByUser(connectionString, id, user.Id);
    if (fileInfo is null)
    {
        return Results.NotFound(new { error = "Файл не найден." });
    }

    var fullPath = Path.Combine(uploadsRoot, fileInfo.StoredName);
    if (!File.Exists(fullPath))
    {
        return Results.NotFound(new { error = "Файл отсутствует на диске." });
    }

    var stream = File.OpenRead(fullPath);
    return Results.File(stream, fileInfo.ContentType, fileInfo.OriginalName);
});

app.MapDelete("/api/files/{id:long}", async (long id, HttpRequest httpRequest) =>
{
    var user = await GetAuthenticatedUser(httpRequest, connectionString);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    var fileInfo = await GetFileOwnedByUser(connectionString, id, user.Id);
    if (fileInfo is null)
    {
        return Results.NotFound(new { error = "Файл не найден." });
    }

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var deleteWhitelist = connection.CreateCommand();
    deleteWhitelist.CommandText = "DELETE FROM file_whitelist WHERE file_id = $fileId;";
    deleteWhitelist.Parameters.AddWithValue("$fileId", id);
    await deleteWhitelist.ExecuteNonQueryAsync();

    var deleteFile = connection.CreateCommand();
    deleteFile.CommandText = "DELETE FROM files WHERE id = $fileId;";
    deleteFile.Parameters.AddWithValue("$fileId", id);
    await deleteFile.ExecuteNonQueryAsync();

    var fullPath = Path.Combine(uploadsRoot, fileInfo.StoredName);
    if (File.Exists(fullPath))
    {
        File.Delete(fullPath);
    }

    return Results.Ok(new { message = "Файл удалён." });
});

app.MapPut("/api/files/{id:long}/rename", async (long id, RenameRequest request, HttpRequest httpRequest) =>
{
    var user = await GetAuthenticatedUser(httpRequest, connectionString);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    if (string.IsNullOrWhiteSpace(request.NewFileName))
    {
        return Results.BadRequest(new { error = "Новое имя файла пустое." });
    }

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    command.CommandText = """
                          UPDATE files
                          SET original_name = $newFileName
                          WHERE id = $fileId AND owner_id = $ownerId;
                          """;
    command.Parameters.AddWithValue("$newFileName", request.NewFileName.Trim());
    command.Parameters.AddWithValue("$fileId", id);
    command.Parameters.AddWithValue("$ownerId", user.Id);

    var updated = await command.ExecuteNonQueryAsync();
    return updated == 0
        ? Results.NotFound(new { error = "Файл не найден." })
        : Results.Ok(new { message = "Файл переименован." });
});

app.MapPost("/api/files/{id:long}/share", async (long id, HttpRequest httpRequest) =>
{
    var user = await GetAuthenticatedUser(httpRequest, connectionString);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var selectCommand = connection.CreateCommand();
    selectCommand.CommandText = """
                                SELECT share_token
                                FROM files
                                WHERE id = $fileId AND owner_id = $ownerId
                                LIMIT 1;
                                """;
    selectCommand.Parameters.AddWithValue("$fileId", id);
    selectCommand.Parameters.AddWithValue("$ownerId", user.Id);

    await using var shareReader = await selectCommand.ExecuteReaderAsync();
    if (!await shareReader.ReadAsync())
    {
        return Results.NotFound(new { error = "Файл не найден." });
    }

    var existingToken = shareReader.IsDBNull(0) ? null : shareReader.GetString(0);
    if (string.IsNullOrWhiteSpace(existingToken))
    {
        existingToken = GenerateToken();
        var updateCommand = connection.CreateCommand();
        updateCommand.CommandText = """
                                    UPDATE files
                                    SET share_token = $shareToken
                                    WHERE id = $fileId AND owner_id = $ownerId;
                                    """;
        updateCommand.Parameters.AddWithValue("$shareToken", existingToken);
        updateCommand.Parameters.AddWithValue("$fileId", id);
        updateCommand.Parameters.AddWithValue("$ownerId", user.Id);
        await updateCommand.ExecuteNonQueryAsync();
    }

    return Results.Ok(new
    {
        shareToken = existingToken,
        shareUrl = $"{httpRequest.Scheme}://{httpRequest.Host}/api/share/{existingToken}"
    });
});

app.MapDelete("/api/files/{id:long}/share", async (long id, HttpRequest httpRequest) =>
{
    var user = await GetAuthenticatedUser(httpRequest, connectionString);
    if (user is null)
    {
        return Results.Unauthorized();
    }

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    command.CommandText = """
                          UPDATE files
                          SET share_token = NULL
                          WHERE id = $fileId AND owner_id = $ownerId;
                          """;
    command.Parameters.AddWithValue("$fileId", id);
    command.Parameters.AddWithValue("$ownerId", user.Id);

    var updated = await command.ExecuteNonQueryAsync();
    return updated == 0
        ? Results.NotFound(new { error = "Файл не найден." })
        : Results.Ok(new { message = "Ссылка на файл отключена." });
});

app.MapGet("/api/share/{token}", async (string token, HttpRequest httpRequest) =>
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT id, owner_id, original_name, stored_name, content_type
                          FROM files
                          WHERE share_token = $token
                          LIMIT 1;
                          """;
    command.Parameters.AddWithValue("$token", token);

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        return Results.NotFound(new { error = "Ссылка не найдена." });
    }

    var fileId = reader.GetInt64(0);
    var ownerId = reader.GetInt64(1);
    var originalName = reader.GetString(2);
    var storedName = reader.GetString(3);
    var contentType = reader.GetString(4);

    var whitelistCountCommand = connection.CreateCommand();
    whitelistCountCommand.CommandText = "SELECT COUNT(1) FROM file_whitelist WHERE file_id = $fileId;";
    whitelistCountCommand.Parameters.AddWithValue("$fileId", fileId);
    var whitelistCount = Convert.ToInt32(await whitelistCountCommand.ExecuteScalarAsync() ?? 0);

    if (whitelistCount > 0)
    {
        var user = await GetAuthenticatedUser(httpRequest, connectionString);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var allowCommand = connection.CreateCommand();
        allowCommand.CommandText = """
                                   SELECT COUNT(1)
                                   FROM file_whitelist
                                   WHERE file_id = $fileId AND user_id = $userId;
                                   """;
        allowCommand.Parameters.AddWithValue("$fileId", fileId);
        allowCommand.Parameters.AddWithValue("$userId", user.Id);

        var allowed = Convert.ToInt32(await allowCommand.ExecuteScalarAsync() ?? 0) > 0 || user.Id == ownerId;
        if (!allowed)
        {
            return Results.StatusCode(StatusCodes.Status403Forbidden);
        }
    }

    var fullPath = Path.Combine(uploadsRoot, storedName);
    if (!File.Exists(fullPath))
    {
        return Results.NotFound(new { error = "Файл отсутствует на диске." });
    }

    var stream = File.OpenRead(fullPath);
    return Results.File(stream, contentType, originalName);
});

app.MapPost("/api/files/{id:long}/whitelist", async (long id, WhitelistRequest request, HttpRequest httpRequest) =>
{
    var owner = await GetAuthenticatedUser(httpRequest, connectionString);
    if (owner is null)
    {
        return Results.Unauthorized();
    }

    if (string.IsNullOrWhiteSpace(request.Username))
    {
        return Results.BadRequest(new { error = "Имя пользователя не указано." });
    }

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var fileExists = connection.CreateCommand();
    fileExists.CommandText = "SELECT COUNT(1) FROM files WHERE id = $fileId AND owner_id = $ownerId;";
    fileExists.Parameters.AddWithValue("$fileId", id);
    fileExists.Parameters.AddWithValue("$ownerId", owner.Id);
    if (Convert.ToInt32(await fileExists.ExecuteScalarAsync() ?? 0) == 0)
    {
        return Results.NotFound(new { error = "Файл не найден." });
    }

    var userCommand = connection.CreateCommand();
    userCommand.CommandText = "SELECT id FROM users WHERE username = $username LIMIT 1;";
    userCommand.Parameters.AddWithValue("$username", request.Username.Trim());
    var targetUserIdObj = await userCommand.ExecuteScalarAsync();
    if (targetUserIdObj is null)
    {
        return Results.NotFound(new { error = "Пользователь для белого списка не найден." });
    }

    var targetUserId = (long)targetUserIdObj;

    var addCommand = connection.CreateCommand();
    addCommand.CommandText = """
                             INSERT OR IGNORE INTO file_whitelist (file_id, user_id)
                             VALUES ($fileId, $userId);
                             """;
    addCommand.Parameters.AddWithValue("$fileId", id);
    addCommand.Parameters.AddWithValue("$userId", targetUserId);
    await addCommand.ExecuteNonQueryAsync();

    return Results.Ok(new { message = "Пользователь добавлен в белый список." });
});

app.MapDelete("/api/files/{id:long}/whitelist/{username}", async (long id, string username, HttpRequest httpRequest) =>
{
    var owner = await GetAuthenticatedUser(httpRequest, connectionString);
    if (owner is null)
    {
        return Results.Unauthorized();
    }

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var fileExists = connection.CreateCommand();
    fileExists.CommandText = "SELECT COUNT(1) FROM files WHERE id = $fileId AND owner_id = $ownerId;";
    fileExists.Parameters.AddWithValue("$fileId", id);
    fileExists.Parameters.AddWithValue("$ownerId", owner.Id);
    if (Convert.ToInt32(await fileExists.ExecuteScalarAsync() ?? 0) == 0)
    {
        return Results.NotFound(new { error = "Файл не найден." });
    }

    var userCommand = connection.CreateCommand();
    userCommand.CommandText = "SELECT id FROM users WHERE username = $username LIMIT 1;";
    userCommand.Parameters.AddWithValue("$username", username.Trim());
    var targetUserIdObj = await userCommand.ExecuteScalarAsync();
    if (targetUserIdObj is null)
    {
        return Results.NotFound(new { error = "Пользователь не найден." });
    }

    var deleteCommand = connection.CreateCommand();
    deleteCommand.CommandText = """
                                DELETE FROM file_whitelist
                                WHERE file_id = $fileId AND user_id = $userId;
                                """;
    deleteCommand.Parameters.AddWithValue("$fileId", id);
    deleteCommand.Parameters.AddWithValue("$userId", (long)targetUserIdObj);
    await deleteCommand.ExecuteNonQueryAsync();

    return Results.Ok(new { message = "Пользователь удалён из белого списка." });
});

app.MapGet("/api/files/{id:long}/whitelist", async (long id, HttpRequest httpRequest) =>
{
    var owner = await GetAuthenticatedUser(httpRequest, connectionString);
    if (owner is null)
    {
        return Results.Unauthorized();
    }

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var fileExists = connection.CreateCommand();
    fileExists.CommandText = "SELECT COUNT(1) FROM files WHERE id = $fileId AND owner_id = $ownerId;";
    fileExists.Parameters.AddWithValue("$fileId", id);
    fileExists.Parameters.AddWithValue("$ownerId", owner.Id);
    if (Convert.ToInt32(await fileExists.ExecuteScalarAsync() ?? 0) == 0)
    {
        return Results.NotFound(new { error = "Файл не найден." });
    }

    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT u.username
                          FROM file_whitelist fw
                          INNER JOIN users u ON u.id = fw.user_id
                          WHERE fw.file_id = $fileId
                          ORDER BY u.username;
                          """;
    command.Parameters.AddWithValue("$fileId", id);

    var users = new List<string>();
    await using var reader = await command.ExecuteReaderAsync();
    while (await reader.ReadAsync())
    {
        users.Add(reader.GetString(0));
    }

    return Results.Ok(users);
});

app.Run();

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
}

static async Task<UserInfo?> GetAuthenticatedUser(HttpRequest request, string connectionString)
{
    var tokenHeader = request.Headers.Authorization.ToString();
    var token = tokenHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
        ? tokenHeader["Bearer ".Length..].Trim()
        : string.Empty;
    if (string.IsNullOrWhiteSpace(token))
    {
        token = request.Cookies["fs_token"]?.Trim() ?? string.Empty;
    }
    if (string.IsNullOrWhiteSpace(token))
    {
        return null;
    }

    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

    var command = connection.CreateCommand();
    command.CommandText = """
                          SELECT u.id, u.username
                          FROM user_sessions s
                          INNER JOIN users u ON u.id = s.user_id
                          WHERE s.token = $token
                            AND s.expires_at > $now
                          LIMIT 1;
                          """;
    command.Parameters.AddWithValue("$token", token);
    command.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("O"));

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        return null;
    }

    return new UserInfo(reader.GetInt64(0), reader.GetString(1));
}

static async Task<FileInfoRow?> GetFileOwnedByUser(string connectionString, long fileId, long ownerId)
{
    await using var connection = new SqliteConnection(connectionString);
    await connection.OpenAsync();

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

static string HashPassword(string password)
{
    var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(password));
    return Convert.ToHexString(hashBytes);
}

static string GenerateToken()
{
    Span<byte> bytes = stackalloc byte[32];
    RandomNumberGenerator.Fill(bytes);
    return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

record AuthRequest(string Username, string Password);
record RenameRequest(string NewFileName);
record WhitelistRequest(string Username);
record UserInfo(long Id, string Username);
record FileInfoRow(long Id, long OwnerId, string OriginalName, string StoredName, string ContentType);
