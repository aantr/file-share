public static class AppConstants
{
    public const long MaxUploadBytes = 50L * 1024 * 1024;
    public const long RequestBodyOverheadBytes = 10L * 1024 * 1024;
    public const string DefaultStorageFolderPath = "storage";
    public const string StorageFolderSettingKey = "StorageFolderPath";
    public const string MaxFileSizeSettingKey = "MaxFileSizeBytes";
    public const string SessionCookieName = "fs_token";
    public const string CsrfHeaderName = "X-CSRF-Token";
    public const int PasswordHashIterations = 120_000;
    public const int PasswordResetTokenLifetimeMinutes = 30;
}
