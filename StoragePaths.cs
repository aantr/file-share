using Microsoft.Data.Sqlite;

public sealed record StoragePaths(string StorageDirectoryPath, string UploadsDirectoryPath, string DatabaseFilePath)
{
    public static StoragePaths Create(string contentRootPath, string storageFolderPath)
    {
        var storageDirectoryPath = Path.IsPathRooted(storageFolderPath)
            ? storageFolderPath
            : Path.Combine(contentRootPath, storageFolderPath);
        var uploadsDirectoryPath = Path.Combine(storageDirectoryPath, "uploads");
        var databaseFilePath = Path.Combine(storageDirectoryPath, "fileshare.db");
        return new StoragePaths(storageDirectoryPath, uploadsDirectoryPath, databaseFilePath);
    }

    public void EnsureDirectories()
    {
        Directory.CreateDirectory(StorageDirectoryPath);
        Directory.CreateDirectory(UploadsDirectoryPath);
    }

    public string BuildConnectionString()
    {
        return new SqliteConnectionStringBuilder
        {
            DataSource = DatabaseFilePath
        }.ToString();
    }
}
