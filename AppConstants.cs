public static class AppConstants
{
    public const string SessionCookieName = "fs_token";
    public const string CsrfHeaderName = "X-CSRF-Token";
    public const int PasswordHashIterations = 120_000;
    public const int PasswordResetTokenLifetimeMinutes = 30;
}
