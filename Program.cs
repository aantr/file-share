using Microsoft.AspNetCore.Http.Features;

// Создание веб-приложения
var builder = WebApplication.CreateBuilder(args);

// Загрузка параметров из appsettings.json
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

// Подготовка путей к папке хранилища и базе SQLite
var storagePaths = StoragePaths.Create(app.Environment.ContentRootPath, storageSettings.StorageFolderPath);
storagePaths.EnsureDirectories();
var connectionString = storagePaths.BuildConnectionString();

// Создание таблиц БД при первом запуске
DatabaseBootstrap.Initialize(connectionString);

// Фронтенд
app.UseDefaultFiles();
app.UseStaticFiles();

// Проверка доступности сервиса
app.MapGet("/api/health", () => Results.Ok(new { service = "FileShareExpert", status = "running" }));

// Параметры загрузки для клиентской части
app.MapGet("/api/settings", () => Results.Ok(new
{
    maxUploadBytes = storageSettings.MaxFileSizeBytes,
    storageFolder = storageSettings.StorageFolderPath
}));

// Регистрация API-маршрутов
AuthEndpoints.Map(app, connectionString);
FileEndpoints.Map(app, connectionString, storagePaths.UploadsDirectoryPath, storageSettings.MaxFileSizeBytes);

app.Run();

// Точка входа для интеграционных тестов
public partial class Program;