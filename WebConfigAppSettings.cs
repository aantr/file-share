using System.Xml.Linq;

public sealed record WebConfigAppSettings(string StorageFolderPath, long MaxFileSizeBytes)
{
    public const long DefaultMaxFileSizeBytes = 50L * 1024 * 1024;
    public const long RequestBodyOverheadBytes = 10L * 1024 * 1024;
    public const string DefaultStorageFolderPath = "storage";
    public const string StorageFolderSettingKey = "StorageFolderPath";
    public const string MaxFileSizeSettingKey = "MaxFileSizeBytes";

    public long MaxRequestBodyBytes => MaxFileSizeBytes + RequestBodyOverheadBytes;

    public static WebConfigAppSettings Load(string contentRootPath)
    {
        var webConfigPath = Path.Combine(contentRootPath, "web.config");
        var storageFolder = DefaultStorageFolderPath;
        var maxFileSizeBytes = DefaultMaxFileSizeBytes;

        if (!File.Exists(webConfigPath))
        {
            return new WebConfigAppSettings(storageFolder, maxFileSizeBytes);
        }

        try
        {
            var document = XDocument.Load(webConfigPath);
            var addNodes = document.Descendants("appSettings").Descendants("add");
            foreach (var node in addNodes)
            {
                var key = node.Attribute("key")?.Value?.Trim();
                var value = node.Attribute("value")?.Value?.Trim();
                if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                if (string.Equals(key, StorageFolderSettingKey, StringComparison.OrdinalIgnoreCase))
                {
                    storageFolder = value;
                }
                else if (string.Equals(key, MaxFileSizeSettingKey, StringComparison.OrdinalIgnoreCase) &&
                         long.TryParse(value, out var parsedMaxFileSizeBytes) &&
                         parsedMaxFileSizeBytes > 0)
                {
                    maxFileSizeBytes = parsedMaxFileSizeBytes;
                }
            }
        }
        catch
        {
            // Fallback to defaults if web.config is missing or malformed.
            return new WebConfigAppSettings(DefaultStorageFolderPath, DefaultMaxFileSizeBytes);
        }

        return new WebConfigAppSettings(storageFolder, maxFileSizeBytes);
    }
}
