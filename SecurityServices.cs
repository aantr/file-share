using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

public static class SecurityServices
{
    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            AppConstants.PasswordHashIterations,
            HashAlgorithmName.SHA256,
            32);
        return $"PBKDF2${AppConstants.PasswordHashIterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool VerifyPassword(string password, string storedHash)
    {
        if (storedHash.StartsWith("PBKDF2$", StringComparison.Ordinal))
        {
            return VerifyPbkdf2Password(password, storedHash);
        }

        var legacyHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password)));
        return string.Equals(legacyHash, storedHash, StringComparison.Ordinal);
    }

    public static bool IsLegacySha256Hash(string storedHash)
    {
        return !storedHash.StartsWith("PBKDF2$", StringComparison.Ordinal);
    }

    public static string GenerateToken()
    {
        Span<byte> bytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static void SetAuthenticationCookie(HttpRequest httpRequest, HttpResponse httpResponse, string sessionToken)
    {
        httpResponse.Cookies.Append(AppConstants.SessionCookieName, sessionToken, new CookieOptions
        {
            Expires = DateTimeOffset.UtcNow.AddDays(30),
            HttpOnly = true,
            Secure = httpRequest.IsHttps,
            IsEssential = true,
            SameSite = SameSiteMode.Lax
        });
    }

    public static async Task<SessionInfo?> GetAuthenticatedSessionAsync(
        HttpRequest request,
        string connectionString,
        bool requireCsrf = false)
    {
        var sessionToken = request.Cookies[AppConstants.SessionCookieName]?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(sessionToken))
        {
            return null;
        }

        var csrfTokenFromHeader = request.Headers[AppConstants.CsrfHeaderName].ToString().Trim();
        if (requireCsrf && string.IsNullOrWhiteSpace(csrfTokenFromHeader))
        {
            return null;
        }

        await using var connection = await SqliteDb.OpenConnectionAsync(connectionString);
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

    private static async Task<SessionInfo?> FindSessionByTokenAsync(SqliteConnection connection, string sessionToken)
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

    private static async Task<SessionInfo> EnsureSessionHasCsrfTokenAsync(SqliteConnection connection, SessionInfo session)
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

    private static bool AreCsrfTokensEqual(string expectedToken, string providedToken)
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

    private static bool VerifyPbkdf2Password(string password, string storedHash)
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
}
