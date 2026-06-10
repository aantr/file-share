var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();

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
