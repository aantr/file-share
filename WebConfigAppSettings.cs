using System.Xml.Linq;

public sealed record WebConfigAppSettings(string StorageFolderPath, long MaxFileSizeBytes)
{
    public long MaxRequestBodyBytes => MaxFileSizeBytes + AppConstants.RequestBodyOverheadBytes;

    public static WebConfigAppSettings Load(string contentRootPath)
    {
        var webConfigPath = Path.Combine(contentRootPath, "web.config");
        var storageFolder = AppConstants.DefaultStorageFolderPath;
        var maxFileSizeBytes = AppConstants.MaxUploadBytes;

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

                if (string.Equals(key, AppConstants.StorageFolderSettingKey, StringComparison.OrdinalIgnoreCase))
                {
                    storageFolder = value;
                }
                else if (string.Equals(key, AppConstants.MaxFileSizeSettingKey, StringComparison.OrdinalIgnoreCase) &&
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
            return new WebConfigAppSettings(AppConstants.DefaultStorageFolderPath, AppConstants.MaxUploadBytes);
        }

        return new WebConfigAppSettings(storageFolder, maxFileSizeBytes);
    }
}
