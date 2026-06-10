using Microsoft.Data.Sqlite;

public static class FileEndpoints
{
    public static void Map(WebApplication app, string connectionString, string uploadsDirectoryPath)
    {
        app.MapPost("/api/files/upload", (HttpRequest httpRequest) =>
            UploadAsync(httpRequest, connectionString, uploadsDirectoryPath));
        app.MapGet("/api/files", (HttpRequest httpRequest) => ListAsync(httpRequest, connectionString));
        app.MapGet("/api/files/{id:long}/download", (long id, HttpRequest httpRequest) =>
            DownloadOwnedAsync(id, httpRequest, connectionString, uploadsDirectoryPath));
        app.MapDelete("/api/files/{id:long}", (long id, HttpRequest httpRequest) =>
            DeleteAsync(id, httpRequest, connectionString, uploadsDirectoryPath));
        app.MapPut("/api/files/{id:long}/rename", (long id, RenameRequest request, HttpRequest httpRequest) =>
            RenameAsync(id, request, httpRequest, connectionString));

        app.MapPost("/api/files/{id:long}/share", (long id, HttpRequest httpRequest) =>
            CreateShareAsync(id, httpRequest, connectionString));
        app.MapDelete("/api/files/{id:long}/share", (long id, HttpRequest httpRequest) =>
            DisableShareAsync(id, httpRequest, connectionString));
        app.MapGet("/api/share/{token}", (string token, HttpRequest httpRequest) =>
            DownloadSharedAsync(token, httpRequest, connectionString, uploadsDirectoryPath));

        app.MapPost("/api/files/{id:long}/whitelist", (long id, WhitelistRequest request, HttpRequest httpRequest) =>
            AddWhitelistAsync(id, request, httpRequest, connectionString));
        app.MapDelete("/api/files/{id:long}/whitelist/{username}", (long id, string username, HttpRequest httpRequest) =>
            RemoveWhitelistAsync(id, username, httpRequest, connectionString));
        app.MapGet("/api/files/{id:long}/whitelist", (long id, HttpRequest httpRequest) =>
            ListWhitelistAsync(id, httpRequest, connectionString));
    }

    private static async Task<IResult> UploadAsync(HttpRequest httpRequest, string connectionString, string uploadsDirectoryPath)
    {
        var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
        if (session is null)
        {
            return Results.Unauthorized();
        }

        if (!httpRequest.HasFormContentType)
        {
            return Results.BadRequest(new { error = "Ожидается multipart/form-data." });
        }

        var form = await httpRequest.ReadFormAsync();
        var file = form.Files["file"] ?? form.Files.FirstOrDefault();
        if (file is null || file.Length <= 0)
        {
            return Results.BadRequest(new { error = "Файл не передан." });
        }

        if (file.Length > AppConstants.MaxUploadBytes)
        {
            return Results.BadRequest(new { error = $"Размер файла не должен превышать {AppConstants.MaxUploadBytes / (1024 * 1024)} MB." });
        }

        var extension = Path.GetExtension(file.FileName);
        var storedName = $"{Guid.NewGuid():N}{extension}";
        var tempPath = Path.Combine(uploadsDirectoryPath, $"{storedName}.uploading");
        var finalPath = Path.Combine(uploadsDirectoryPath, storedName);

        await using (var stream = File.Create(tempPath))
        {
            await file.CopyToAsync(stream);
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        using var tx = connection.BeginTransaction();
        try
        {
            var insert = connection.CreateCommand();
            insert.Transaction = tx;
            insert.CommandText = """
                                 INSERT INTO files (owner_id, original_name, stored_name, size, content_type, created_at)
                                 VALUES ($ownerId, $originalName, $storedName, $size, $contentType, $createdAt);
                                 """;
            insert.Parameters.AddWithValue("$ownerId", session.User.Id);
            insert.Parameters.AddWithValue("$originalName", file.FileName);
            insert.Parameters.AddWithValue("$storedName", storedName);
            insert.Parameters.AddWithValue("$size", file.Length);
            insert.Parameters.AddWithValue("$contentType", file.ContentType ?? "application/octet-stream");
            insert.Parameters.AddWithValue("$createdAt", DateTime.UtcNow.ToString("O"));
            await insert.ExecuteNonQueryAsync();

            var idCommand = connection.CreateCommand();
            idCommand.Transaction = tx;
            idCommand.CommandText = "SELECT last_insert_rowid();";
            var fileId = (long)(await idCommand.ExecuteScalarAsync() ?? 0L);

            File.Move(tempPath, finalPath, overwrite: false);
            tx.Commit();

            return Results.Ok(new
            {
                message = "Файл загружен.",
                file = new { id = fileId, name = file.FileName, size = file.Length }
            });
        }
        catch
        {
            tx.Rollback();
            SqliteDb.TryDeleteFileIfExists(tempPath);
            SqliteDb.TryDeleteFileIfExists(finalPath);
            return Results.StatusCode(StatusCodes.Status500InternalServerError);
        }
    }

    private static async Task<IResult> ListAsync(HttpRequest httpRequest, string connectionString)
    {
        var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString);
        if (session is null)
        {
            return Results.Unauthorized();
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var command = connection.CreateCommand();
        command.CommandText = """
                              SELECT id, original_name, size, content_type, created_at, share_token
                              FROM files
                              WHERE owner_id = $ownerId
                              ORDER BY created_at DESC;
                              """;
        command.Parameters.AddWithValue("$ownerId", session.User.Id);

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
                shareUrl = string.IsNullOrWhiteSpace(shareToken)
                    ? null
                    : $"{httpRequest.Scheme}://{httpRequest.Host}/api/share/{shareToken}"
            });
        }

        return Results.Ok(files);
    }

    private static async Task<IResult> DownloadOwnedAsync(long fileId, HttpRequest httpRequest, string connectionString, string uploadsDirectoryPath)
    {
        var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString);
        if (session is null)
        {
            return Results.Unauthorized();
        }

        var fileInfo = await GetOwnedFileAsync(connectionString, fileId, session.User.Id);
        if (fileInfo is null)
        {
            return Results.NotFound(new { error = "Файл не найден." });
        }

        var filePath = Path.Combine(uploadsDirectoryPath, fileInfo.StoredName);
        if (!File.Exists(filePath))
        {
            return Results.NotFound(new { error = "Файл отсутствует на диске." });
        }

        return Results.File(File.OpenRead(filePath), fileInfo.ContentType, fileInfo.OriginalName);
    }

    private static async Task<IResult> DeleteAsync(long fileId, HttpRequest httpRequest, string connectionString, string uploadsDirectoryPath)
    {
        var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
        if (session is null)
        {
            return Results.Unauthorized();
        }

        var fileInfo = await GetOwnedFileAsync(connectionString, fileId, session.User.Id);
        if (fileInfo is null)
        {
            return Results.NotFound(new { error = "Файл не найден." });
        }

        var fullPath = Path.Combine(uploadsDirectoryPath, fileInfo.StoredName);
        if (!File.Exists(fullPath))
        {
            return Results.NotFound(new { error = "Файл отсутствует на диске." });
        }

        var quarantinePath = Path.Combine(uploadsDirectoryPath, $"{fileInfo.StoredName}.deleting.{Guid.NewGuid():N}");
        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        using var tx = connection.BeginTransaction();

        try
        {
            File.Move(fullPath, quarantinePath, overwrite: false);

            var deleteWhitelist = connection.CreateCommand();
            deleteWhitelist.Transaction = tx;
            deleteWhitelist.CommandText = "DELETE FROM file_whitelist WHERE file_id = $fileId;";
            deleteWhitelist.Parameters.AddWithValue("$fileId", fileId);
            await deleteWhitelist.ExecuteNonQueryAsync();

            var deleteFile = connection.CreateCommand();
            deleteFile.Transaction = tx;
            deleteFile.CommandText = "DELETE FROM files WHERE id = $fileId;";
            deleteFile.Parameters.AddWithValue("$fileId", fileId);
            var affected = await deleteFile.ExecuteNonQueryAsync();
            if (affected == 0)
            {
                throw new InvalidOperationException("File row was not deleted.");
            }

            tx.Commit();
            SqliteDb.TryDeleteFileIfExists(quarantinePath);
            return Results.Ok(new { message = "Файл удалён." });
        }
        catch
        {
            tx.Rollback();
            if (File.Exists(quarantinePath) && !File.Exists(fullPath))
            {
                File.Move(quarantinePath, fullPath, overwrite: false);
            }
            return Results.StatusCode(StatusCodes.Status500InternalServerError);
        }
    }

    private static async Task<IResult> RenameAsync(long fileId, RenameRequest request, HttpRequest httpRequest, string connectionString)
    {
        var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
        if (session is null)
        {
            return Results.Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(request.NewFileName))
        {
            return Results.BadRequest(new { error = "Новое имя файла пустое." });
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var command = connection.CreateCommand();
        command.CommandText = """
                              UPDATE files
                              SET original_name = $newFileName
                              WHERE id = $fileId AND owner_id = $ownerId;
                              """;
        command.Parameters.AddWithValue("$newFileName", request.NewFileName.Trim());
        command.Parameters.AddWithValue("$fileId", fileId);
        command.Parameters.AddWithValue("$ownerId", session.User.Id);

        var updated = await command.ExecuteNonQueryAsync();
        return updated == 0
            ? Results.NotFound(new { error = "Файл не найден." })
            : Results.Ok(new { message = "Файл переименован." });
    }

    private static async Task<IResult> CreateShareAsync(long fileId, HttpRequest httpRequest, string connectionString)
    {
        var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
        if (session is null)
        {
            return Results.Unauthorized();
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var tokenCommand = connection.CreateCommand();
        tokenCommand.CommandText = """
                                   SELECT share_token
                                   FROM files
                                   WHERE id = $fileId AND owner_id = $ownerId
                                   LIMIT 1;
                                   """;
        tokenCommand.Parameters.AddWithValue("$fileId", fileId);
        tokenCommand.Parameters.AddWithValue("$ownerId", session.User.Id);

        string? shareToken;
        await using (var reader = await tokenCommand.ExecuteReaderAsync())
        {
            if (!await reader.ReadAsync())
            {
                return Results.NotFound(new { error = "Файл не найден." });
            }
            shareToken = reader.IsDBNull(0) ? string.Empty : reader.GetString(0);
        }

        if (string.IsNullOrWhiteSpace(shareToken))
        {
            shareToken = SecurityServices.GenerateToken();
            var updateCommand = connection.CreateCommand();
            updateCommand.CommandText = """
                                        UPDATE files
                                        SET share_token = $shareToken
                                        WHERE id = $fileId AND owner_id = $ownerId;
                                        """;
            updateCommand.Parameters.AddWithValue("$shareToken", shareToken);
            updateCommand.Parameters.AddWithValue("$fileId", fileId);
            updateCommand.Parameters.AddWithValue("$ownerId", session.User.Id);
            await updateCommand.ExecuteNonQueryAsync();
        }

        return Results.Ok(new
        {
            shareToken,
            shareUrl = $"{httpRequest.Scheme}://{httpRequest.Host}/api/share/{shareToken}"
        });
    }

    private static async Task<IResult> DisableShareAsync(long fileId, HttpRequest httpRequest, string connectionString)
    {
        var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
        if (session is null)
        {
            return Results.Unauthorized();
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var command = connection.CreateCommand();
        command.CommandText = """
                              UPDATE files
                              SET share_token = NULL
                              WHERE id = $fileId AND owner_id = $ownerId;
                              """;
        command.Parameters.AddWithValue("$fileId", fileId);
        command.Parameters.AddWithValue("$ownerId", session.User.Id);
        var updated = await command.ExecuteNonQueryAsync();

        return updated == 0
            ? Results.NotFound(new { error = "Файл не найден." })
            : Results.Ok(new { message = "Ссылка на файл отключена." });
    }

    private static async Task<IResult> DownloadSharedAsync(string token, HttpRequest httpRequest, string connectionString, string uploadsDirectoryPath)
    {
        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var command = connection.CreateCommand();
        command.CommandText = """
                              SELECT id, owner_id, original_name, stored_name, content_type
                              FROM files
                              WHERE share_token = $token
                              LIMIT 1;
                              """;
        command.Parameters.AddWithValue("$token", token);

        SharedFileInfo? sharedFile;
        await using (var reader = await command.ExecuteReaderAsync())
        {
            if (!await reader.ReadAsync())
            {
                return Results.NotFound(new { error = "Ссылка не найдена." });
            }

            sharedFile = new SharedFileInfo(
                reader.GetInt64(0),
                reader.GetInt64(1),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4));
        }

        var whitelistCountCommand = connection.CreateCommand();
        whitelistCountCommand.CommandText = "SELECT COUNT(1) FROM file_whitelist WHERE file_id = $fileId;";
        whitelistCountCommand.Parameters.AddWithValue("$fileId", sharedFile.FileId);
        var whitelistExists = Convert.ToInt32(await whitelistCountCommand.ExecuteScalarAsync() ?? 0) > 0;

        if (whitelistExists)
        {
            var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString);
            if (session is null)
            {
                return Results.Unauthorized();
            }

            var allowCommand = connection.CreateCommand();
            allowCommand.CommandText = """
                                       SELECT COUNT(1)
                                       FROM file_whitelist
                                       WHERE file_id = $fileId AND user_id = $userId;
                                       """;
            allowCommand.Parameters.AddWithValue("$fileId", sharedFile.FileId);
            allowCommand.Parameters.AddWithValue("$userId", session.User.Id);
            var userAllowed = Convert.ToInt32(await allowCommand.ExecuteScalarAsync() ?? 0) > 0 || session.User.Id == sharedFile.OwnerId;
            if (!userAllowed)
            {
                return Results.StatusCode(StatusCodes.Status403Forbidden);
            }
        }

        var filePath = Path.Combine(uploadsDirectoryPath, sharedFile.StoredName);
        if (!File.Exists(filePath))
        {
            return Results.NotFound(new { error = "Файл отсутствует на диске." });
        }

        return Results.File(File.OpenRead(filePath), sharedFile.ContentType, sharedFile.OriginalName);
    }

    private static async Task<IResult> AddWhitelistAsync(long fileId, WhitelistRequest request, HttpRequest httpRequest, string connectionString)
    {
        var ownerSession = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
        if (ownerSession is null)
        {
            return Results.Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(request.Username))
        {
            return Results.BadRequest(new { error = "Имя пользователя не указано." });
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        if (!await OwnerHasFileAsync(connection, fileId, ownerSession.User.Id))
        {
            return Results.NotFound(new { error = "Файл не найден." });
        }

        var userId = await GetUserIdByUsernameAsync(connection, request.Username.Trim());
        if (userId is null)
        {
            return Results.NotFound(new { error = "Пользователь для белого списка не найден." });
        }

        var command = connection.CreateCommand();
        command.CommandText = """
                              INSERT OR IGNORE INTO file_whitelist (file_id, user_id)
                              VALUES ($fileId, $userId);
                              """;
        command.Parameters.AddWithValue("$fileId", fileId);
        command.Parameters.AddWithValue("$userId", userId.Value);
        await command.ExecuteNonQueryAsync();

        return Results.Ok(new { message = "Пользователь добавлен в белый список." });
    }

    private static async Task<IResult> RemoveWhitelistAsync(long fileId, string username, HttpRequest httpRequest, string connectionString)
    {
        var ownerSession = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
        if (ownerSession is null)
        {
            return Results.Unauthorized();
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        if (!await OwnerHasFileAsync(connection, fileId, ownerSession.User.Id))
        {
            return Results.NotFound(new { error = "Файл не найден." });
        }

        var userId = await GetUserIdByUsernameAsync(connection, username.Trim());
        if (userId is null)
        {
            return Results.NotFound(new { error = "Пользователь не найден." });
        }

        var command = connection.CreateCommand();
        command.CommandText = """
                              DELETE FROM file_whitelist
                              WHERE file_id = $fileId AND user_id = $userId;
                              """;
        command.Parameters.AddWithValue("$fileId", fileId);
        command.Parameters.AddWithValue("$userId", userId.Value);
        await command.ExecuteNonQueryAsync();

        return Results.Ok(new { message = "Пользователь удалён из белого списка." });
    }

    private static async Task<IResult> ListWhitelistAsync(long fileId, HttpRequest httpRequest, string connectionString)
    {
        var ownerSession = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString);
        if (ownerSession is null)
        {
            return Results.Unauthorized();
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        if (!await OwnerHasFileAsync(connection, fileId, ownerSession.User.Id))
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
        command.Parameters.AddWithValue("$fileId", fileId);

        var users = new List<string>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            users.Add(reader.GetString(0));
        }

        return Results.Ok(users);
    }

    private static async Task<FileInfoRow?> GetOwnedFileAsync(string connectionString, long fileId, long ownerId)
    {
        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
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

    private static async Task<bool> OwnerHasFileAsync(SqliteConnection connection, long fileId, long ownerId)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(1) FROM files WHERE id = $fileId AND owner_id = $ownerId;";
        command.Parameters.AddWithValue("$fileId", fileId);
        command.Parameters.AddWithValue("$ownerId", ownerId);
        return Convert.ToInt32(await command.ExecuteScalarAsync() ?? 0) > 0;
    }

    private static async Task<long?> GetUserIdByUsernameAsync(SqliteConnection connection, string username)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT id FROM users WHERE username = $username LIMIT 1;";
        command.Parameters.AddWithValue("$username", username);
        var result = await command.ExecuteScalarAsync();
        return result is null ? null : (long)result;
    }
}
