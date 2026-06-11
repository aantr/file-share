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
    public async Task Register_WhenAlreadyAuthenticated_ReturnsConflictWithCode()
    {
        await using var app = await TestApp.CreateAsync();
        var session = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");

        var response = await session.Client.PostAsJsonAsync("/api/auth/register", new
        {
            username = app.CreateUniqueUsername(),
            email = $"{Guid.NewGuid():N}@test.local",
            password = "pass1234"
        });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("AUTH_ALREADY_AUTHENTICATED", json.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Login_WithInvalidPassword_ReturnsUnauthorized()
    {
        await using var app = await TestApp.CreateAsync();
        var username = app.CreateUniqueUsername();
        await app.RegisterAsync(username, "pass1234");

        var wrongPasswordClient = app.CreateClient();
        var loginResponse = await wrongPasswordClient.PostAsJsonAsync("/api/auth/login", new
        {
            username,
            password = "wrong-pass"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, loginResponse.StatusCode);
        var json = await loginResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("AUTH_INVALID_CREDENTIALS", json.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Login_WhenAlreadyAuthenticated_ReturnsConflictWithCode()
    {
        await using var app = await TestApp.CreateAsync();
        var username = app.CreateUniqueUsername();
        var session = await app.RegisterAndLoginAsync(username, "pass1234");

        var secondLogin = await session.Client.PostAsJsonAsync("/api/auth/login", new
        {
            username,
            password = "pass1234"
        });

        Assert.Equal(HttpStatusCode.Conflict, secondLogin.StatusCode);
        var json = await secondLogin.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("AUTH_ALREADY_AUTHENTICATED", json.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Me_WithoutAuth_ReturnsUnauthorizedWithCode()
    {
        await using var app = await TestApp.CreateAsync();
        var client = app.CreateClient();

        var response = await client.GetAsync("/api/auth/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("AUTH_ALREADY_LOGGED_OUT", json.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Logout_WithValidCsrf_LogsOutAndRepeatedLogoutReturnsConflict()
    {
        await using var app = await TestApp.CreateAsync();
        var session = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");

        var firstLogout = await app.SendMutatingAsync(session, HttpMethod.Post, "/api/auth/logout");
        Assert.Equal(HttpStatusCode.OK, firstLogout.StatusCode);

        var secondLogout = await app.SendMutatingAsync(session, HttpMethod.Post, "/api/auth/logout");
        Assert.Equal(HttpStatusCode.Conflict, secondLogout.StatusCode);
        var json = await secondLogout.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("AUTH_ALREADY_LOGGED_OUT", json.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Logout_WithoutCsrf_ReturnsUnauthorizedWithInvalidStateCode()
    {
        await using var app = await TestApp.CreateAsync();
        var session = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");

        var response = await session.Client.PostAsync("/api/auth/logout", content: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("AUTH_INVALID_STATE", json.GetProperty("code").GetString());
    }

    [Fact]
    public async Task ChangePassword_Success_InvalidatesOldPassword()
    {
        await using var app = await TestApp.CreateAsync();
        var username = app.CreateUniqueUsername();
        var session = await app.RegisterAndLoginAsync(username, "old-pass");

        var changeResponse = await app.SendMutatingJsonAsync(
            session,
            HttpMethod.Post,
            "/api/auth/change-password",
            JsonContent.Create(new { currentPassword = "old-pass", newPassword = "new-pass" }));
        Assert.Equal(HttpStatusCode.OK, changeResponse.StatusCode);

        await app.LogoutWithCsrfAsync(session);

        var oldLoginClient = app.CreateClient();
        var oldLoginResponse = await oldLoginClient.PostAsJsonAsync("/api/auth/login", new
        {
            username,
            password = "old-pass"
        });
        Assert.Equal(HttpStatusCode.Unauthorized, oldLoginResponse.StatusCode);

        var newLoginClient = app.CreateClient();
        var newLoginResponse = await newLoginClient.PostAsJsonAsync("/api/auth/login", new
        {
            username,
            password = "new-pass"
        });
        Assert.Equal(HttpStatusCode.OK, newLoginResponse.StatusCode);
    }

    [Fact]
    public async Task ChangePassword_WithWrongCurrentPassword_ReturnsUnauthorized()
    {
        await using var app = await TestApp.CreateAsync();
        var session = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");

        var response = await app.SendMutatingJsonAsync(
            session,
            HttpMethod.Post,
            "/api/auth/change-password",
            JsonContent.Create(new { currentPassword = "wrong", newPassword = "new-pass" }));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("AUTH_INVALID_CREDENTIALS", json.GetProperty("code").GetString());
    }

    [Fact]
    public async Task ForgotAndResetPassword_WorksAndTokenCannotBeReused()
    {
        await using var app = await TestApp.CreateAsync();
        var username = app.CreateUniqueUsername();
        var email = $"{username}@test.local";
        await app.RegisterAsync(username, "pass1234", email);

        var anonymousClient = app.CreateClient();
        var forgotResponse = await anonymousClient.PostAsJsonAsync("/api/auth/forgot-password", new { email });
        Assert.Equal(HttpStatusCode.OK, forgotResponse.StatusCode);
        var forgotJson = await forgotResponse.Content.ReadFromJsonAsync<JsonElement>();
        var resetToken = forgotJson.GetProperty("resetToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(resetToken));

        var resetResponse = await anonymousClient.PostAsJsonAsync("/api/auth/reset-password", new
        {
            email,
            resetToken,
            newPassword = "new-pass"
        });
        Assert.Equal(HttpStatusCode.OK, resetResponse.StatusCode);

        var reuseResponse = await anonymousClient.PostAsJsonAsync("/api/auth/reset-password", new
        {
            email,
            resetToken,
            newPassword = "another-pass"
        });
        Assert.Equal(HttpStatusCode.Unauthorized, reuseResponse.StatusCode);
        var reuseJson = await reuseResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("AUTH_INVALID_RESET_TOKEN", reuseJson.GetProperty("code").GetString());

        var loginClient = app.CreateClient();
        var loginResponse = await loginClient.PostAsJsonAsync("/api/auth/login", new { username, password = "new-pass" });
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);
    }

    [Fact]
    public async Task ForgotPassword_WhenEmailNotFound_ReturnsNotFoundCode()
    {
        await using var app = await TestApp.CreateAsync();
        var client = app.CreateClient();

        var response = await client.PostAsJsonAsync("/api/auth/forgot-password", new { email = "missing@test.local" });

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("AUTH_EMAIL_NOT_FOUND", json.GetProperty("code").GetString());
    }

    [Fact]
    public async Task ResetPassword_WithInvalidToken_ReturnsUnauthorized()
    {
        await using var app = await TestApp.CreateAsync();
        var username = app.CreateUniqueUsername();
        var email = $"{username}@test.local";
        await app.RegisterAsync(username, "pass1234", email);

        var client = app.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/reset-password", new
        {
            email,
            resetToken = "invalid-token",
            newPassword = "new-pass"
        });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("AUTH_INVALID_RESET_TOKEN", json.GetProperty("code").GetString());
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
    public async Task FilesList_WithoutAuth_ReturnsUnauthorized()
    {
        await using var app = await TestApp.CreateAsync();
        var client = app.CreateClient();

        var response = await client.GetAsync("/api/files");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Upload_WithoutMultipartFormData_ReturnsBadRequest()
    {
        await using var app = await TestApp.CreateAsync();
        var session = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/files/upload")
        {
            Content = JsonContent.Create(new { fake = true })
        };
        request.Headers.Add("X-CSRF-Token", session.CsrfToken);

        var response = await session.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Upload_TooLargeFile_ReturnsBadRequest()
    {
        await using var app = await TestApp.CreateAsync();
        var session = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");

        var payload = new byte[AppConstants.MaxUploadBytes + 1];
        var form = new MultipartFormDataContent
        {
            { new ByteArrayContent(payload), "file", "huge.bin" }
        };

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/files/upload")
        {
            Content = form
        };
        request.Headers.Add("X-CSRF-Token", session.CsrfToken);

        var response = await session.Client.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Rename_EmptyName_ReturnsBadRequest()
    {
        await using var app = await TestApp.CreateAsync();
        var session = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var uploaded = await app.UploadFileAsync(session, "x.txt", "data");

        var response = await app.SendMutatingJsonAsync(
            session,
            HttpMethod.Put,
            $"/api/files/{uploaded.FileId}/rename",
            JsonContent.Create(new { newFileName = "   " }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task DownloadOwned_WhenUserHasNoAccess_ReturnsNotFound()
    {
        await using var app = await TestApp.CreateAsync();
        var owner = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var stranger = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var uploaded = await app.UploadFileAsync(owner, "private.txt", "private");

        var response = await stranger.Client.GetAsync($"/api/files/{uploaded.FileId}/download");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Delete_WithoutCsrf_ReturnsUnauthorized()
    {
        await using var app = await TestApp.CreateAsync();
        var session = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var uploaded = await app.UploadFileAsync(session, "x.txt", "x");

        var response = await session.Client.DeleteAsync($"/api/files/{uploaded.FileId}");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
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
    public async Task CreateShare_CalledTwice_ReusesSameToken()
    {
        await using var app = await TestApp.CreateAsync();
        var owner = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var uploaded = await app.UploadFileAsync(owner, "public.txt", "data");

        var first = await app.SendMutatingAsync(owner, HttpMethod.Post, $"/api/files/{uploaded.FileId}/share");
        var firstJson = await first.Content.ReadFromJsonAsync<JsonElement>();
        var firstToken = firstJson.GetProperty("shareToken").GetString();

        var second = await app.SendMutatingAsync(owner, HttpMethod.Post, $"/api/files/{uploaded.FileId}/share");
        var secondJson = await second.Content.ReadFromJsonAsync<JsonElement>();
        var secondToken = secondJson.GetProperty("shareToken").GetString();

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(firstToken, secondToken);
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
    public async Task DisableShare_MakesLinkUnavailable()
    {
        await using var app = await TestApp.CreateAsync();
        var owner = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var uploaded = await app.UploadFileAsync(owner, "public.txt", "content");

        var shareResponse = await app.SendMutatingAsync(owner, HttpMethod.Post, $"/api/files/{uploaded.FileId}/share");
        var token = (await shareResponse.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("shareToken").GetString();

        var disableResponse = await app.SendMutatingAsync(owner, HttpMethod.Delete, $"/api/files/{uploaded.FileId}/share");
        Assert.Equal(HttpStatusCode.OK, disableResponse.StatusCode);

        var anonymousClient = app.CreateClient();
        var sharedAfterDisable = await anonymousClient.GetAsync($"/api/share/{token}");
        Assert.Equal(HttpStatusCode.NotFound, sharedAfterDisable.StatusCode);
    }

    [Fact]
    public async Task Whitelist_ListAndRemove_FlowWorks()
    {
        await using var app = await TestApp.CreateAsync();
        var owner = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var allowed = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var uploaded = await app.UploadFileAsync(owner, "private.txt", "secret");

        var addResponse = await app.SendMutatingJsonAsync(
            owner,
            HttpMethod.Post,
            $"/api/files/{uploaded.FileId}/whitelist",
            JsonContent.Create(new { username = allowed.Username }));
        Assert.Equal(HttpStatusCode.OK, addResponse.StatusCode);

        var listBeforeRemove = await owner.Client.GetFromJsonAsync<string[]>($"/api/files/{uploaded.FileId}/whitelist");
        Assert.NotNull(listBeforeRemove);
        Assert.Contains(allowed.Username, listBeforeRemove!);

        var removeResponse = await app.SendMutatingAsync(owner, HttpMethod.Delete, $"/api/files/{uploaded.FileId}/whitelist/{allowed.Username}");
        Assert.Equal(HttpStatusCode.OK, removeResponse.StatusCode);

        var listAfterRemove = await owner.Client.GetFromJsonAsync<string[]>($"/api/files/{uploaded.FileId}/whitelist");
        Assert.NotNull(listAfterRemove);
        Assert.DoesNotContain(allowed.Username, listAfterRemove!);
    }

    [Fact]
    public async Task Whitelist_AddUnknownUser_ReturnsNotFound()
    {
        await using var app = await TestApp.CreateAsync();
        var owner = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var uploaded = await app.UploadFileAsync(owner, "private.txt", "secret");

        var response = await app.SendMutatingJsonAsync(
            owner,
            HttpMethod.Post,
            $"/api/files/{uploaded.FileId}/whitelist",
            JsonContent.Create(new { username = "missing-user" }));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Whitelist_WhenNonOwnerTriesToModify_ReturnsNotFound()
    {
        await using var app = await TestApp.CreateAsync();
        var owner = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var stranger = await app.RegisterAndLoginAsync(app.CreateUniqueUsername(), "pass1234");
        var uploaded = await app.UploadFileAsync(owner, "private.txt", "secret");

        var response = await app.SendMutatingJsonAsync(
            stranger,
            HttpMethod.Post,
            $"/api/files/{uploaded.FileId}/whitelist",
            JsonContent.Create(new { username = owner.Username }));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
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

    public Task RegisterAsync(string username, string password)
    {
        return RegisterAsync(username, password, $"{username}@test.local");
    }

    public async Task RegisterAsync(string username, string password, string email)
    {
        var client = _factory.CreateClient();
        var registerResponse = await client.PostAsJsonAsync("/api/auth/register", new { username, email, password });
        Assert.Equal(HttpStatusCode.OK, registerResponse.StatusCode);
    }

    public async Task<AuthSession> RegisterAndLoginAsync(string username, string password)
    {
        await RegisterAsync(username, password);
        return await LoginAsync(username, password);
    }

    public async Task<AuthSession> LoginAsync(string username, string password)
    {
        var client = _factory.CreateClient();
        var loginResponse = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        Assert.Equal(HttpStatusCode.OK, loginResponse.StatusCode);

        var loginJson = await loginResponse.Content.ReadFromJsonAsync<JsonElement>();
        var csrfToken = loginJson.GetProperty("csrfToken").GetString();
        Assert.False(string.IsNullOrWhiteSpace(csrfToken));
        return new AuthSession(client, username, csrfToken!);
    }

    public async Task LogoutWithCsrfAsync(AuthSession session)
    {
        var response = await SendMutatingAsync(session, HttpMethod.Post, "/api/auth/logout");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
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
