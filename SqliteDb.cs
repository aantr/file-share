using Microsoft.Data.Sqlite;

public static class SqliteDb
{
    public static async Task<SqliteConnection> OpenConnectionAsync(string connectionString)
    {
        var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();
        return connection;
    }

    public static void TryDeleteFileIfExists(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }
}
