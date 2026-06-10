using Microsoft.Data.Sqlite;

public static class AuthEndpoints
{
    private static class AuthErrorCodes
    {
        public const string AlreadyAuthenticated = "AUTH_ALREADY_AUTHENTICATED";
        public const string AlreadyLoggedOut = "AUTH_ALREADY_LOGGED_OUT";
        public const string InvalidCredentials = "AUTH_INVALID_CREDENTIALS";
        public const string InvalidState = "AUTH_INVALID_STATE";
        public const string InvalidEmail = "AUTH_INVALID_EMAIL";
        public const string EmailInUse = "AUTH_EMAIL_ALREADY_IN_USE";
        public const string EmailNotFound = "AUTH_EMAIL_NOT_FOUND";
        public const string InvalidResetToken = "AUTH_INVALID_RESET_TOKEN";
    }

    public static void Map(WebApplication app, string connectionString)
    {
        app.MapPost("/api/auth/register", (RegisterRequest request, HttpRequest httpRequest) => RegisterAsync(request, httpRequest, connectionString));
        app.MapPost("/api/auth/login", (AuthRequest request, HttpRequest httpRequest, HttpResponse httpResponse) =>
            LoginAsync(request, httpRequest, httpResponse, connectionString));
        app.MapGet("/api/auth/me", (HttpRequest httpRequest) => MeAsync(httpRequest, connectionString));
        app.MapPost("/api/auth/logout", (HttpRequest httpRequest, HttpResponse httpResponse) =>
            LogoutAsync(httpRequest, httpResponse, connectionString));
        app.MapPost("/api/auth/change-password", (ChangePasswordRequest request, HttpRequest httpRequest) =>
            ChangePasswordAsync(request, httpRequest, connectionString));
        app.MapPost("/api/auth/forgot-password", (ForgotPasswordRequest request, HttpRequest httpRequest) =>
            ForgotPasswordAsync(request, httpRequest, connectionString));
        app.MapPost("/api/auth/reset-password", (ResetPasswordRequest request, HttpRequest httpRequest) =>
            ResetPasswordAsync(request, httpRequest, connectionString));
    }

    private static async Task<IResult> RegisterAsync(RegisterRequest request, HttpRequest httpRequest, string connectionString)
    {
        if (await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString) is not null)
        {
            return AuthError(
                AuthErrorCodes.AlreadyAuthenticated,
                "Вы уже авторизованы. Сначала выйдите, если хотите зарегистрировать нового пользователя.",
                StatusCodes.Status409Conflict);
        }

        if (string.IsNullOrWhiteSpace(request.Username) ||
            string.IsNullOrWhiteSpace(request.Password) ||
            string.IsNullOrWhiteSpace(request.Email))
        {
            return Results.BadRequest(new { error = "Имя пользователя, email и пароль обязательны." });
        }

        if (request.Username.Length < 3 || request.Password.Length < 4)
        {
            return Results.BadRequest(new { error = "Минимум 3 символа для логина и 4 для пароля." });
        }

        var normalizedEmail = request.Email.Trim().ToLowerInvariant();
        if (!IsValidEmail(normalizedEmail))
        {
            return AuthError(
                AuthErrorCodes.InvalidEmail,
                "Некорректный email.",
                StatusCodes.Status400BadRequest);
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var command = connection.CreateCommand();
        command.CommandText = """
                              INSERT INTO users (username, email, password_hash, created_at)
                              VALUES ($username, $email, $passwordHash, $createdAt);
                              """;
        command.Parameters.AddWithValue("$username", request.Username.Trim());
        command.Parameters.AddWithValue("$email", normalizedEmail);
        command.Parameters.AddWithValue("$passwordHash", SecurityServices.HashPassword(request.Password));
        command.Parameters.AddWithValue("$createdAt", DateTime.UtcNow.ToString("O"));

        try
        {
            await command.ExecuteNonQueryAsync();
            return Results.Ok(new { message = "Пользователь зарегистрирован." });
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            var isEmailConflict = ex.Message.Contains("users.email", StringComparison.OrdinalIgnoreCase) ||
                                  ex.Message.Contains("idx_users_email", StringComparison.OrdinalIgnoreCase);
            return isEmailConflict
                ? AuthError(AuthErrorCodes.EmailInUse, "Пользователь с таким email уже существует.", StatusCodes.Status409Conflict)
                : Results.Conflict(new { error = "Пользователь с таким именем уже существует." });
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
            user = new { id = credentials.UserId, username = credentials.Username, email = credentials.Email }
        });
    }

    private static async Task<IResult> MeAsync(HttpRequest httpRequest, string connectionString)
    {
        var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString);
        if (session is null)
        {
            return AuthError(
                AuthErrorCodes.AlreadyLoggedOut,
                "Вы не авторизованы. Выполните вход.",
                StatusCodes.Status401Unauthorized);
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var email = await GetUserEmailAsync(connection, session.User.Id);
        return Results.Ok(new
        {
            id = session.User.Id,
            username = session.User.Username,
            email,
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

    private static async Task<IResult> ChangePasswordAsync(ChangePasswordRequest request, HttpRequest httpRequest, string connectionString)
    {
        var session = await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString, requireCsrf: true);
        if (session is null)
        {
            return AuthError(
                AuthErrorCodes.AlreadyLoggedOut,
                "Для смены пароля нужно выполнить вход.",
                StatusCodes.Status401Unauthorized);
        }

        if (string.IsNullOrWhiteSpace(request.CurrentPassword) || string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return Results.BadRequest(new { error = "Текущий и новый пароль обязательны." });
        }

        if (request.NewPassword.Length < 4)
        {
            return Results.BadRequest(new { error = "Новый пароль должен быть не короче 4 символов." });
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var credentials = await GetUserCredentialsByIdAsync(connection, session.User.Id);
        if (credentials is null || !SecurityServices.VerifyPassword(request.CurrentPassword, credentials.PasswordHash))
        {
            return AuthError(
                AuthErrorCodes.InvalidCredentials,
                "Текущий пароль введен неверно.",
                StatusCodes.Status401Unauthorized);
        }

        var updateCommand = connection.CreateCommand();
        updateCommand.CommandText = """
                                    UPDATE users
                                    SET password_hash = $passwordHash
                                    WHERE id = $userId;
                                    """;
        updateCommand.Parameters.AddWithValue("$passwordHash", SecurityServices.HashPassword(request.NewPassword));
        updateCommand.Parameters.AddWithValue("$userId", session.User.Id);
        await updateCommand.ExecuteNonQueryAsync();

        return Results.Ok(new { message = "Пароль успешно изменен." });
    }

    private static async Task<IResult> ForgotPasswordAsync(ForgotPasswordRequest request, HttpRequest httpRequest, string connectionString)
    {
        if (await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString) is not null)
        {
            return AuthError(
                AuthErrorCodes.AlreadyAuthenticated,
                "Вы уже авторизованы. Для смены пароля используйте форму смены пароля.",
                StatusCodes.Status409Conflict);
        }

        if (string.IsNullOrWhiteSpace(request.Email))
        {
            return Results.BadRequest(new { error = "Email обязателен." });
        }

        var normalizedEmail = request.Email.Trim().ToLowerInvariant();
        if (!IsValidEmail(normalizedEmail))
        {
            return AuthError(
                AuthErrorCodes.InvalidEmail,
                "Некорректный email.",
                StatusCodes.Status400BadRequest);
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var userId = await GetUserIdByEmailAsync(connection, normalizedEmail);
        if (userId is null)
        {
            return AuthError(
                AuthErrorCodes.EmailNotFound,
                "Пользователь с таким email не найден.",
                StatusCodes.Status404NotFound);
        }

        var resetToken = SecurityServices.GenerateToken();
        var insertCommand = connection.CreateCommand();
        insertCommand.CommandText = """
                                    INSERT INTO password_reset_tokens (user_id, token, expires_at, created_at)
                                    VALUES ($userId, $token, $expiresAt, $createdAt);
                                    """;
        insertCommand.Parameters.AddWithValue("$userId", userId.Value);
        insertCommand.Parameters.AddWithValue("$token", resetToken);
        insertCommand.Parameters.AddWithValue("$expiresAt", DateTime.UtcNow.AddMinutes(AppConstants.PasswordResetTokenLifetimeMinutes).ToString("O"));
        insertCommand.Parameters.AddWithValue("$createdAt", DateTime.UtcNow.ToString("O"));
        await insertCommand.ExecuteNonQueryAsync();

        // Demo mode: возвращаем токен в ответе, чтобы можно было протестировать восстановление без почтового сервиса.
        return Results.Ok(new
        {
            message = "Инструкция по восстановлению отправлена на email (demo mode).",
            resetToken
        });
    }

    private static async Task<IResult> ResetPasswordAsync(ResetPasswordRequest request, HttpRequest httpRequest, string connectionString)
    {
        if (await SecurityServices.GetAuthenticatedSessionAsync(httpRequest, connectionString) is not null)
        {
            return AuthError(
                AuthErrorCodes.AlreadyAuthenticated,
                "Вы уже авторизованы. Для смены пароля используйте форму смены пароля.",
                StatusCodes.Status409Conflict);
        }

        if (string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.ResetToken) ||
            string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return Results.BadRequest(new { error = "Email, токен и новый пароль обязательны." });
        }

        if (request.NewPassword.Length < 4)
        {
            return Results.BadRequest(new { error = "Новый пароль должен быть не короче 4 символов." });
        }

        var normalizedEmail = request.Email.Trim().ToLowerInvariant();
        if (!IsValidEmail(normalizedEmail))
        {
            return AuthError(
                AuthErrorCodes.InvalidEmail,
                "Некорректный email.",
                StatusCodes.Status400BadRequest);
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
        var tokenRow = await GetValidResetTokenRowAsync(connection, normalizedEmail, request.ResetToken.Trim());
        if (tokenRow is null)
        {
            return AuthError(
                AuthErrorCodes.InvalidResetToken,
                "Токен восстановления недействителен или истек.",
                StatusCodes.Status401Unauthorized);
        }

        var updateUser = connection.CreateCommand();
        updateUser.CommandText = """
                                 UPDATE users
                                 SET password_hash = $passwordHash
                                 WHERE id = $userId;
                                 """;
        updateUser.Parameters.AddWithValue("$passwordHash", SecurityServices.HashPassword(request.NewPassword));
        updateUser.Parameters.AddWithValue("$userId", tokenRow.UserId);
        await updateUser.ExecuteNonQueryAsync();

        var useToken = connection.CreateCommand();
        useToken.CommandText = """
                               UPDATE password_reset_tokens
                               SET used_at = $usedAt
                               WHERE id = $id;
                               """;
        useToken.Parameters.AddWithValue("$usedAt", DateTime.UtcNow.ToString("O"));
        useToken.Parameters.AddWithValue("$id", tokenRow.TokenRowId);
        await useToken.ExecuteNonQueryAsync();

        return Results.Ok(new { message = "Пароль успешно восстановлен. Теперь можно войти с новым паролем." });
    }

    private static IResult AuthError(string code, string message, int statusCode)
    {
        return Results.Json(new { code, error = message }, statusCode: statusCode);
    }

    private static bool IsValidEmail(string email)
    {
        var atPos = email.IndexOf('@');
        var dotPos = email.LastIndexOf('.');
        return atPos > 0 && dotPos > atPos + 1 && dotPos < email.Length - 1;
    }

    private static async Task<UserCredentials?> GetUserCredentialsByUsernameAsync(SqliteConnection connection, string username)
    {
        var command = connection.CreateCommand();
        command.CommandText = """
                              SELECT id, username, password_hash, email
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
            reader.GetString(2),
            reader.IsDBNull(3) ? null : reader.GetString(3));
    }

    private static async Task<UserCredentials?> GetUserCredentialsByIdAsync(SqliteConnection connection, long userId)
    {
        var command = connection.CreateCommand();
        command.CommandText = """
                              SELECT id, username, password_hash, email
                              FROM users
                              WHERE id = $userId
                              LIMIT 1;
                              """;
        command.Parameters.AddWithValue("$userId", userId);

        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return null;
        }

        return new UserCredentials(
            reader.GetInt64(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.IsDBNull(3) ? null : reader.GetString(3));
    }

    private static async Task<string?> GetUserEmailAsync(SqliteConnection connection, long userId)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT email FROM users WHERE id = $userId LIMIT 1;";
        command.Parameters.AddWithValue("$userId", userId);
        var result = await command.ExecuteScalarAsync();
        return result is null || result is DBNull ? null : result.ToString();
    }

    private static async Task<long?> GetUserIdByEmailAsync(SqliteConnection connection, string email)
    {
        var command = connection.CreateCommand();
        command.CommandText = "SELECT id FROM users WHERE email = $email LIMIT 1;";
        command.Parameters.AddWithValue("$email", email);
        var result = await command.ExecuteScalarAsync();
        return result is null ? null : (long)result;
    }

    private static async Task<ResetTokenRow?> GetValidResetTokenRowAsync(SqliteConnection connection, string email, string token)
    {
        var command = connection.CreateCommand();
        command.CommandText = """
                              SELECT prt.id, prt.user_id
                              FROM password_reset_tokens prt
                              INNER JOIN users u ON u.id = prt.user_id
                              WHERE u.email = $email
                                AND prt.token = $token
                                AND prt.used_at IS NULL
                                AND prt.expires_at > $now
                              LIMIT 1;
                              """;
        command.Parameters.AddWithValue("$email", email);
        command.Parameters.AddWithValue("$token", token);
        command.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("O"));

        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return null;
        }

        return new ResetTokenRow(reader.GetInt64(0), reader.GetInt64(1));
    }

    private sealed record ResetTokenRow(long TokenRowId, long UserId);
}
