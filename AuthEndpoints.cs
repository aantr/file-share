using Microsoft.Data.Sqlite;

public static class AuthEndpoints
{
    public static void Map(WebApplication app, string connectionString)
    {
        app.MapPost("/api/auth/register", (AuthRequest request) => RegisterAsync(request, connectionString));
        app.MapPost("/api/auth/login", (AuthRequest request, HttpRequest httpRequest, HttpResponse httpResponse) =>
            LoginAsync(request, httpRequest, httpResponse, connectionString));
        app.MapGet("/api/auth/me", (HttpRequest httpRequest) => MeAsync(httpRequest, connectionString));
        app.MapPost("/api/auth/logout", (HttpRequest httpRequest, HttpResponse httpResponse) =>
            LogoutAsync(httpRequest, httpResponse, connectionString));
    }

    private static async Task<IResult> RegisterAsync(AuthRequest request, string connectionString)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            return Results.BadRequest(new { error = "Имя пользователя и пароль обязательны." });
        }

        if (request.Username.Length < 3 || request.Password.Length < 4)
        {
            return Results.BadRequest(new { error = "Минимум 3 символа для логина и 4 для пароля." });
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var command = connection.CreateCommand();
        command.CommandText = """
                              INSERT INTO users (username, password_hash, created_at)
                              VALUES ($username, $passwordHash, $createdAt);
                              """;
        command.Parameters.AddWithValue("$username", request.Username.Trim());
        command.Parameters.AddWithValue("$passwordHash", SecurityServices.HashPassword(request.Password));
        command.Parameters.AddWithValue("$createdAt", DateTime.UtcNow.ToString("O"));

        try
        {
            await command.ExecuteNonQueryAsync();
            return Results.Ok(new { message = "Пользователь зарегистрирован." });
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            return Results.Conflict(new { error = "Пользователь с таким именем уже существует." });
        }
    }

    private static async Task<IResult> LoginAsync(
        AuthRequest request,
        HttpRequest httpRequest,
        HttpResponse httpResponse,
        string connectionString)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            return Results.BadRequest(new { error = "Имя пользователя и пароль обязательны." });
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var credentials = await GetUserCredentialsByUsernameAsync(connection, request.Username.Trim());
        if (credentials is null || !SecurityServices.VerifyPassword(request.Password, credentials.PasswordHash))
        {
            return Results.Unauthorized();
        }

        if (SecurityServices.IsLegacySha256Hash(credentials.PasswordHash))
        {
            var rehashCommand = connection.CreateCommand();
            rehashCommand.CommandText = """
                                        UPDATE users
                                        SET password_hash = $passwordHash
                                        WHERE id = $userId;
                                        """;
            rehashCommand.Parameters.AddWithValue("$passwordHash", SecurityServices.HashPassword(request.Password));
            rehashCommand.Parameters.AddWithValue("$userId", credentials.UserId);
            await rehashCommand.ExecuteNonQueryAsync();
        }

        var sessionToken = SecurityServices.GenerateToken();
        var csrfToken = SecurityServices.GenerateToken();
        var sessionCommand = connection.CreateCommand();
        sessionCommand.CommandText = """
                                     INSERT INTO user_sessions (token, user_id, expires_at, csrf_token)
                                     VALUES ($token, $userId, $expiresAt, $csrfToken);
                                     """;
        sessionCommand.Parameters.AddWithValue("$token", sessionToken);
        sessionCommand.Parameters.AddWithValue("$userId", credentials.UserId);
        sessionCommand.Parameters.AddWithValue("$expiresAt", DateTime.UtcNow.AddDays(30).ToString("O"));
        sessionCommand.Parameters.AddWithValue("$csrfToken", csrfToken);
        await sessionCommand.ExecuteNonQueryAsync();

        SecurityServices.SetAuthenticationCookie(httpRequest, httpResponse, sessionToken);

        return Results.Ok(new
        {
            csrfToken,
            user = new { id = credentials.UserId, username = credentials.Username }
        });
    }

    private static async Task<IResult> MeAsync(HttpRequest httpRequest, string connectionString)
    {
        var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString);
        return session is null
            ? Results.Unauthorized()
            : Results.Ok(new
            {
                id = session.User.Id,
                username = session.User.Username,
                csrfToken = session.CsrfToken
            });
    }

    private static async Task<IResult> LogoutAsync(HttpRequest httpRequest, HttpResponse httpResponse, string connectionString)
    {
        var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
        if (session is null)
        {
            return Results.Unauthorized();
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM user_sessions WHERE token = $token;";
        command.Parameters.AddWithValue("$token", session.SessionToken);
        await command.ExecuteNonQueryAsync();

        httpResponse.Cookies.Delete(AppConstants.SessionCookieName);
        return Results.Ok(new { message = "Вы вышли из системы." });
    }

    private static async Task<UserCredentials?> GetUserCredentialsByUsernameAsync(SqliteConnection connection, string username)
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

        return new UserCredentials(reader.GetInt64(0), reader.GetString(1), reader.GetString(2));
    }
}
