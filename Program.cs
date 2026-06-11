using Microsoft.AspNetCore.Http.Features;

var builder = WebApplication.CreateBuilder(args);
var storageSettings = WebConfigAppSettings.Load(builder.Environment.ContentRootPath);
builder.Services.AddEndpointsApiExplorer();
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = storageSettings.MaxRequestBodyBytes;
});
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = storageSettings.MaxRequestBodyBytes;
});

var app = builder.Build();

var storagePaths = StoragePaths.Create(app.Environment.ContentRootPath, storageSettings.StorageFolderPath);
storagePaths.EnsureDirectories();
var connectionString = storagePaths.BuildConnectionString();

DatabaseBootstrap.Initialize(connectionString);

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/health", () => Results.Ok(new { service = "FileShareExpert", status = "running" }));
app.MapGet("/api/settings", () => Results.Ok(new
{
    maxUploadBytes = storageSettings.MaxFileSizeBytes,
    storageFolder = storageSettings.StorageFolderPath
}));
AuthEndpoints.Map(app, connectionString);
FileEndpoints.Map(app, connectionString, storagePaths.UploadsDirectoryPath, storageSettings.MaxFileSizeBytes);

app.Run();

public partial class Program;
