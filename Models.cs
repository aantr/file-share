public record AuthRequest(string Username, string Password);
public record RenameRequest(string NewFileName);
public record WhitelistRequest(string Username);
public record UserInfo(long Id, string Username);
public record SessionInfo(string SessionToken, UserInfo User, string CsrfToken);
public record FileInfoRow(long Id, long OwnerId, string OriginalName, string StoredName, string ContentType);
public record UserCredentials(long UserId, string Username, string PasswordHash);
public record SharedFileInfo(long FileId, long OwnerId, string OriginalName, string StoredName, string ContentType);
