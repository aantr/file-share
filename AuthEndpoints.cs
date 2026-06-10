using Microsoft.Data.Sqlite;

public static class AuthEndpoints
{
    private static class AuthErrorCodes
    {
        public const string AlreadyAuthenticated = "AUTH_ALREADY_AUTHENTICATED";
        public const string AlreadyLoggedOut = "AUTH_ALREADY_LOGGED_OUT";
        public const string InvalidCredentials = "AUTH_INVALID_CREDENTIALS";
        public const string InvalidState = "AUTH_INVALID_STATE";
    }

    public static void Map(WebApplication app, string connectionString)
    {
        app.MapPost("/api/auth/register", (AuthRequest request, HttpRequest httpRequest) => RegisterAsync(request, httpRequest, connectionString));
        app.MapPost("/api/auth/login", (AuthRequest request, HttpRequest httpRequest, HttpResponse httpResponse) =>
            LoginAsync(request, httpRequest, httpResponse, connectionString));
        app.MapGet("/api/auth/me", (HttpRequest httpRequest) => MeAsync(httpRequest, connectionString));
        app.MapPost("/api/auth/logout", (HttpRequest httpRequest, HttpResponse httpResponse) =>
            LogoutAsync(httpRequest, httpResponse, connectionString));
    }

    private static async Task<IResult> RegisterAsync(AuthRequest request, HttpRequest httpRequest, string connectionString)
    {
        if (await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString) is not null)
        {
            return AuthError(
                AuthErrorCodes.AlreadyAuthenticated,
                "Вы уже авторизованы. Сначала выйдите, если хотите зарегистрировать нового пользователя.",
                StatusCodes.Status409Conflict);
        }

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
        var existingSession = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString);
        if (existingSession is not null)
        {
            return AuthError(
                AuthErrorCodes.AlreadyAuthenticated,
                $"Вы уже вошли как {existingSession.User.Username}. Сначала выполните выход, чтобы войти под другим пользователем.",
                StatusCodes.Status409Conflict);
        }

        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
        {
            return Results.BadRequest(new { error = "Имя пользователя и пароль обязательны." });
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var credentials = await GetUserCredentialsByUsernameAsync(connection, request.Username.Trim());
        if (credentials is null || !SecurityServices.VerifyPassword(request.Password, credentials.PasswordHash))
        {
            return AuthError(
                AuthErrorCodes.InvalidCredentials,
                "Неверный логин или пароль.",
                StatusCodes.Status401Unauthorized);
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
            ? AuthError(
                AuthErrorCodes.AlreadyLoggedOut,
                "Вы не авторизованы. Выполните вход.",
                StatusCodes.Status401Unauthorized)
            : Results.Ok(new
            {
                id = session.User.Id,
                username = session.User.Username,
                csrfToken = session.CsrfToken
            });
    }

    private static async Task<IResult> LogoutAsync(HttpRequest httpRequest, HttpResponse httpResponse, string connectionString)
    {
        var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString);
        if (session is null)
        {
            return AuthError(
                AuthErrorCodes.AlreadyLoggedOut,
                "Вы уже вышли из системы.",
                StatusCodes.Status409Conflict);
        }

        var csrfValidatedSession = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
        if (csrfValidatedSession is null)
        {
            return AuthError(
                AuthErrorCodes.InvalidState,
                "Некорректный или отсутствующий CSRF-токен. Обновите страницу и повторите попытку.",
                StatusCodes.Status401Unauthorized);
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM user_sessions WHERE token = $token;";
        command.Parameters.AddWithValue("$token", csrfValidatedSession.SessionToken);
        await command.ExecuteNonQueryAsync();

        httpResponse.Cookies.Delete(AppConstants.SessionCookieName);
        return Results.Ok(new { message = "Вы вышли из системы." });
    }

    private static IResult AuthError(string code, string message, int statusCode)
    {
        return Results.Json(new { code, error = message }, statusCode: statusCode);
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
