using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace FileShareExpert.Tests;

public sealed class FileShareApiTests
{
    [Fact]
    public async Task RegisterLoginAndMe_ReturnsCurrentUser()
    {
        await using var app = await TestApp.CreateAsync();
        var auth = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");

        var meResponse = await auth.Client.GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.OK, meResponse.StatusCode);

        var meJson = await meResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(auth.Username, meJson.GetProperty("username").GetString());
        Assert.False(string.IsNullOrWhiteSpace(meJson.GetProperty("csrfToken").GetString()));
    }

    [Fact]
    public async Task UploadRenameDownloadDelete_FlowWorks()
    {
        await using var app = await TestApp.CreateAsync();
        var auth = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");

        var uploaded = await app.UploadFileAsync(auth, "notes.txt", "hello");
        Assert.True(uploaded.FileId > 0);

        var filesAfterUpload = await app.GetOwnedFilesAsync(auth.Client);
        Assert.Contains(filesAfterUpload, x => x.Id == uploaded.FileId && x.Name == "notes.txt");

        var renameResponse = await app.SendMutatingJsonAsync(
            auth,
            HttpMethod.Put,
            $"/api/files/{uploaded.FileId}/rename",
            JsonContent.Create(new { newFileName = "renamed.txt" }));
        Assert.Equal(HttpStatusCode.OK, renameResponse.StatusCode);

        var filesAfterRename = await app.GetOwnedFilesAsync(auth.Client);
        Assert.Contains(filesAfterRename, x => x.Id == uploaded.FileId && x.Name == "renamed.txt");

        var downloaded = await auth.Client.GetStringAsync($"/api/files/{uploaded.FileId}/download");
        Assert.Equal("hello", downloaded);

        var deleteResponse = await app.SendMutatingAsync(auth, HttpMethod.Delete, $"/api/files/{uploaded.FileId}");
        Assert.Equal(HttpStatusCode.OK, deleteResponse.StatusCode);

        var filesAfterDelete = await app.GetOwnedFilesAsync(auth.Client);
        Assert.DoesNotContain(filesAfterDelete, x => x.Id == uploaded.FileId);
    }

    [Fact]
    public async Task ShareWithoutWhitelist_IsAccessibleAnonymously()
    {
        await using var app = await TestApp.CreateAsync();
        var owner = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var uploaded = await app.UploadFileAsync(owner, "public.txt", "public-content");

        var shareResponse = await app.SendMutatingAsync(owner, HttpMethod.Post, $"/api/files/{uploaded.FileId}/share");
        Assert.Equal(HttpStatusCode.OK, shareResponse.StatusCode);

        var shareJson = await shareResponse.Content.ReadFromJsonAsync<JsonElement>();
        var shareToken = shareJson.GetProperty("shareToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(shareToken));

        var anonymousClient = app.CreateClient();
        var anonymousContent = await anonymousClient.GetStringAsync($"/api/share/{shareToken}");
        Assert.Equal("public-content", anonymousContent);
    }

    [Fact]
    public async Task ShareWithWhitelist_RestrictsAccessToAllowedUsers()
    {
        await using var app = await TestApp.CreateAsync();
        var owner = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var allowedUser = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var blockedUser = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");

        var uploaded = await app.UploadFileAsync(owner, "private.txt", "secret");
        var shareResponse = await app.SendMutatingAsync(owner, HttpMethod.Post, $"/api/files/{uploaded.FileId}/share");
        var shareJson = await shareResponse.Content.ReadFromJsonAsync<JsonElement>();
        var shareToken = shareJson.GetProperty("shareToken").GetString()!;

        var addAllowedResponse = await app.SendMutatingJsonAsync(
            owner,
            HttpMethod.Post,
            $"/api/files/{uploaded.FileId}/whitelist",
            JsonContent.Create(new { username = allowedUser.Username }));
        Assert.Equal(HttpStatusCode.OK, addAllowedResponse.StatusCode);

        var anonymousClient = app.CreateClient();
        var anonymousResponse = await anonymousClient.GetAsync($"/api/share/{shareToken}");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);

        var allowedResponse = await allowedUser.Client.GetAsync($"/api/share/{shareToken}");
        Assert.Equal(HttpStatusCode.OK, allowedResponse.StatusCode);
        var allowedContent = await allowedResponse.Content.ReadAsStringAsync();
        Assert.Equal("secret", allowedContent);

        var blockedResponse = await blockedUser.Client.GetAsync($"/api/share/{shareToken}");
        Assert.Equal(HttpStatusCode.Forbidden, blockedResponse.StatusCode);
    }

    [Fact]
    public async Task MutatingRequestsWithoutCsrf_AreRejected()
    {
        await using var app = await TestApp.CreateAsync();
        var auth = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");

        var content = new MultipartFormDataContent
        {
            { new ByteArrayContent(Encoding.UTF8.GetBytes("x")), "file", "x.txt" }
        };

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/files/upload")
        {
            Content = content
        };

        var response = await auth.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}

file sealed class TestApp : IAsyncDisposable
{
    private readonly TestWebApplicationFactory _factory;

    private TestApp(TestWebApplicationFactory factory)
    {
        _factory = factory;
    }

    public static async Task<TestApp> CreateAsync()
    {
        var factory = new TestWebApplicationFactory();
        _ = factory.CreateClient();
        return await Task.FromResult(new TestApp(factory));
    }

    public HttpClient CreateClient() => _factory.CreateClient();

    public string CreateUniqueUsername() => $"user_{Guid.NewGuid():N}";

    public async Task<AuthSession> RegisterAndLoginAsync(string username, string password)
    {
        var client = _factory.CreateClient();

        var registerResponse = await client.PostAsJsonAsync("/api/auth/register", new { username, password });
        Assert.True(registerResponse.StatusCode is HttpStatusCode.OK or HttpStatusCode.Conflict);

        var loginResponse = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var loginJson = await loginResponse.Content.ReadFromJsonAsync<JsonElement>();
        var csrfToken = loginJson.GetProperty("csrfToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(csrfToken));

        return new AuthSession(client, username, csrfToken!);
    }

    public async Task<UploadedFile> UploadFileAsync(AuthSession session, string fileName, string content)
    {
        var form = new MultipartFormDataContent
        {
            { new ByteArrayContent(Encoding.UTF8.GetBytes(content)), "file", fileName }
        };

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/files/upload")
        {
            Content = form
        };
        request.Headers.Add("X-CSRF-Token", session.CsrfToken);

        var response = await session.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        var id = json.GetProperty("file").GetProperty("id").GetInt64();
        var name = json.GetProperty("file").GetProperty("name").GetString()!;
        return new UploadedFile(id, name);
    }

    public async Task<List<FileListItem>> GetOwnedFilesAsync(HttpClient client)
    {
        var response = await client.GetAsync("/api/files");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        var files = new List<FileListItem>();

        foreach (var item in json.EnumerateArray())
        {
            files.Add(new FileListItem(
                item.GetProperty("id").GetInt64(),
                item.GetProperty("name").GetString() ?? string.Empty));
        }

        return files;
    }

    public Task<HttpResponseMessage> SendMutatingAsync(AuthSession session, HttpMethod method, string url)
    {
        return SendMutatingJsonAsync(session, method, url, null);
    }

    public async Task<HttpResponseMessage> SendMutatingJsonAsync(
        AuthSession session,
        HttpMethod method,
        string url,
        HttpContent? content)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Add("X-CSRF-Token", session.CsrfToken);
        if (content is not null)
        {
            request.Content = content;
        }

        return await session.Client.SendAsync(request);
    }

    public async ValueTask DisposeAsync()
    {
        _factory.Dispose();
        await Task.CompletedTask;
    }
}

file sealed class TestWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly string _contentRootPath = Path.Combine(
        Path.GetTempPath(),
        "FileShareExpertTests",
        Guid.NewGuid().ToString("N"));

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Directory.CreateDirectory(_contentRootPath);
        builder.UseEnvironment("Development");
        builder.UseSetting(WebHostDefaults.ContentRootKey, _contentRootPath);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        TryDeleteDirectoryWithRetry(_contentRootPath);
    }

    private static void TryDeleteDirectoryWithRetry(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        const int maxAttempts = 8;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                Directory.Delete(path, recursive: true);
                return;
            }
            catch (IOException)
            {
                if (attempt == maxAttempts)
                {
                    return;
                }

                Thread.Sleep(75 * attempt);
            }
            catch (UnauthorizedAccessException)
            {
                if (attempt == maxAttempts)
                {
                    return;
                }

                Thread.Sleep(75 * attempt);
            }
        }
    }
}

file sealed record AuthSession(HttpClient Client, string Username, string CsrfToken);
file sealed record UploadedFile(long FileId, string Name);
file sealed record FileListItem(long Id, string Name);
