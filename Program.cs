using Microsoft.AspNetCore.Http.Features;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = AppConstants.MaxRequestBodyBytes;
});
builder.Services.Configure<FormOptions>(options =>
{
    options.MultipartBodyLengthLimit = AppConstants.MaxRequestBodyBytes;
});

var app = builder.Build();

var storagePaths = StoragePaths.Create(app.Environment.ContentRootPath);
storagePaths.EnsureDirectories();
var connectionString = storagePaths.BuildConnectionString();

DatabaseBootstrap.Initialize(connectionString);

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/api/health", () => Results.Ok(new { service = "FileShareExpert", status = "running" }));
AuthEndpoints.Map(app, connectionString);
FileEndpoints.Map(app, connectionString, storagePaths.UploadsDirectoryPath);

app.Run();

public partial class Program;
