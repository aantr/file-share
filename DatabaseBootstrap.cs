using Microsoft.Data.Sqlite;

public static class DatabaseBootstrap
{
    public static void Initialize(string connectionString)
    {
        using var connection = new SqliteConnection(connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = """
                              CREATE TABLE IF NOT EXISTS users (
                                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                                  username TEXT NOT NULL UNIQUE,
                                  password_hash TEXT NOT NULL,
                                  created_at TEXT NOT NULL
                              );

                              CREATE TABLE IF NOT EXISTS user_sessions (
                                  token TEXT PRIMARY KEY,
                                  user_id INTEGER NOT NULL,
                                  expires_at TEXT NOT NULL,
                                  csrf_token TEXT NOT NULL DEFAULT '',
                                  FOREIGN KEY (user_id) REFERENCES users(id)
                              );

                              CREATE TABLE IF NOT EXISTS files (
                                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                                  owner_id INTEGER NOT NULL,
                                  original_name TEXT NOT NULL,
                                  stored_name TEXT NOT NULL,
                                  size INTEGER NOT NULL,
                                  content_type TEXT NOT NULL,
                                  created_at TEXT NOT NULL,
                                  share_token TEXT UNIQUE,
                                  FOREIGN KEY (owner_id) REFERENCES users(id)
                              );

                              CREATE TABLE IF NOT EXISTS file_whitelist (
                                  file_id INTEGER NOT NULL,
                                  user_id INTEGER NOT NULL,
                                  PRIMARY KEY (file_id, user_id),
                                  FOREIGN KEY (file_id) REFERENCES files(id),
                                  FOREIGN KEY (user_id) REFERENCES users(id)
                              );
                              """;
        command.ExecuteNonQuery();

        EnsureUserSessionsCsrfColumnExists(connection);
    }

    private static void EnsureUserSessionsCsrfColumnExists(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA table_info(user_sessions);";

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var existingColumnName = reader.GetString(1);
            if (string.Equals(existingColumnName, "csrf_token", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
        }

        using var alterCommand = connection.CreateCommand();
        alterCommand.CommandText = "ALTER TABLE user_sessions ADD COLUMN csrf_token TEXT NOT NULL DEFAULT '';";
        alterCommand.ExecuteNonQuery();
    }
}
