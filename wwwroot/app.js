const state = {
  csrfToken: sessionStorage.getItem("fs_csrf") || "",
  user: null
};

const el = {
  username: document.getElementById("username"),
  password: document.getElementById("password"),
  registerBtn: document.getElementById("registerBtn"),
  loginBtn: document.getElementById("loginBtn"),
  logoutBtn: document.getElementById("logoutBtn"),
  authInfo: document.getElementById("authInfo"),
  uploadFileInput: document.getElementById("uploadFileInput"),
  uploadBtn: document.getElementById("uploadBtn"),
  refreshFilesBtn: document.getElementById("refreshFilesBtn"),
  filesContainer: document.getElementById("filesContainer"),
  shareInput: document.getElementById("shareInput"),
  downloadByShareBtn: document.getElementById("downloadByShareBtn"),
  messageBox: document.getElementById("messageBox"),
  log: document.getElementById("log"),
  fileTemplate: document.getElementById("fileTemplate")
};

let messageTimer = null;

function showError(message) {
  if (!el.messageBox) return;
  el.messageBox.textContent = message;
  el.messageBox.classList.remove("hidden");
  el.messageBox.classList.add("error");

  if (messageTimer) {
    clearTimeout(messageTimer);
  }
  messageTimer = setTimeout(() => {
    el.messageBox.classList.add("hidden");
    el.messageBox.textContent = "";
  }, 6000);
}

function writeLog(message, isError = false) {
  const prefix = new Date().toLocaleTimeString();
  const line = `[${prefix}] ${isError ? "ERROR: " : ""}${message}\n`;
  el.log.textContent = line + el.log.textContent;
  if (isError) {
    showError(message);
  }
}

function csrfHeaders() {
  const headers = {};
  if (state.csrfToken) {
    headers["X-CSRF-Token"] = state.csrfToken;
  }
  return headers;
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    ...options
  });
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const message = payload?.error || payload?.message || `HTTP ${response.status}`;
    throw new Error(message);
  }
  return payload;
}

function setCsrfToken(token) {
  state.csrfToken = token || "";
  if (state.csrfToken) {
    sessionStorage.setItem("fs_csrf", state.csrfToken);
  } else {
    sessionStorage.removeItem("fs_csrf");
  }
}

function setAuthInfo() {
  if (state.user) {
    el.authInfo.textContent = `Авторизован: ${state.user.username}`;
  } else {
    el.authInfo.textContent = "Не авторизован";
  }
}

async function fetchMe() {
  try {
    const data = await requestJson("/api/auth/me", {
      method: "GET"
    });
    state.user = { id: data.id, username: data.username };
    setCsrfToken(data.csrfToken || "");
    setAuthInfo();
  } catch {
    state.user = null;
    setCsrfToken("");
    setAuthInfo();
  }
}

async function register() {
  const username = el.username.value.trim();
  const password = el.password.value;
  if (!username || !password) {
    writeLog("Введите логин и пароль.", true);
    return;
  }

  try {
    await requestJson("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    writeLog(`Пользователь ${username} зарегистрирован.`);
  } catch (error) {
    writeLog(error.message, true);
  }
}

async function login() {
  const username = el.username.value.trim();
  const password = el.password.value;

  try {
    const data = await requestJson("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    setCsrfToken(data.csrfToken || "");
    state.user = data.user;
    setAuthInfo();
    writeLog(`Вход выполнен: ${state.user.username}`);
    await loadFiles();
  } catch (error) {
    writeLog(error.message, true);
  }
}

async function logout() {
  try {
    await requestJson("/api/auth/logout", {
      method: "POST",
      headers: csrfHeaders()
    });
    state.user = null;
    setCsrfToken("");
    setAuthInfo();
    el.filesContainer.innerHTML = "";
    writeLog("Выход выполнен.");
  } catch (error) {
    writeLog(error.message || "Не удалось выполнить выход.", true);
  }
}

async function uploadFile() {
  const file = el.uploadFileInput.files?.[0];
  if (!file) {
    writeLog("Выберите файл для загрузки.", true);
    return;
  }

  try {
    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch("/api/files/upload", {
      method: "POST",
      credentials: "same-origin",
      headers: csrfHeaders(),
      body: formData
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload?.error || `HTTP ${response.status}`);
    }

    writeLog(`Файл загружен: ${payload.file?.name || file.name}`);
    el.uploadFileInput.value = "";
    await loadFiles();
  } catch (error) {
    writeLog(error.message, true);
  }
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function tokenFromInput(raw) {
  const value = raw.trim();
  if (!value) return "";
  if (value.includes("/api/share/")) {
    const idx = value.lastIndexOf("/api/share/");
    return value.slice(idx + "/api/share/".length).trim();
  }
  return value;
}

function fileNameFromDisposition(disposition) {
  if (!disposition) return "";
  const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      return utf8Match[1];
    }
  }
  const basicMatch = disposition.match(/filename="?([^"]+)"?/i);
  return basicMatch?.[1] || "";
}

async function downloadUrl(url, fallbackFileName) {
  const response = await fetch(url, {
    credentials: "same-origin"
  });

  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try {
      const payload = await response.json();
      message = payload?.error || payload?.message || message;
    } catch {
      // Keep default message for non-JSON response
    }
    throw new Error(message);
  }

  const blob = await response.blob();
  const disposition = response.headers.get("Content-Disposition");
  const finalName = fileNameFromDisposition(disposition) || fallbackFileName || "download.bin";

  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = finalName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
}

async function loadWhitelist(fileId, container) {
  try {
    const users = await requestJson(`/api/files/${fileId}/whitelist`, {
      method: "GET"
    });

    container.innerHTML = "";
    if (!Array.isArray(users) || users.length === 0) {
      container.textContent = "Белый список пуст.";
      return;
    }

    for (const username of users) {
      const pill = document.createElement("span");
      pill.className = "pill";
      pill.textContent = username;

      const removeBtn = document.createElement("button");
      removeBtn.textContent = "x";
      removeBtn.title = "Удалить из whitelist";
      removeBtn.addEventListener("click", async () => {
        try {
          await requestJson(`/api/files/${fileId}/whitelist/${encodeURIComponent(username)}`, {
            method: "DELETE",
            headers: csrfHeaders()
          });
          writeLog(`Пользователь ${username} удален из whitelist.`);
          await loadWhitelist(fileId, container);
        } catch (error) {
          writeLog(error.message, true);
        }
      });

      pill.appendChild(removeBtn);
      container.appendChild(pill);
    }
  } catch (error) {
    writeLog(error.message, true);
  }
}

function renderFiles(files) {
  el.filesContainer.innerHTML = "";
  if (!Array.isArray(files) || files.length === 0) {
    el.filesContainer.textContent = "Файлов пока нет.";
    return;
  }

  for (const file of files) {
    const node = el.fileTemplate.content.firstElementChild.cloneNode(true);
    node.querySelector(".file-name").textContent = file.name;
    node.querySelector(".file-meta").textContent = `${formatSize(file.size)} | id=${file.id}`;

    const shareUrlInput = node.querySelector(".share-url");
    shareUrlInput.value = file.shareUrl || "";

    node.querySelector(".download-btn").addEventListener("click", async () => {
      try {
        await downloadUrl(`/api/files/${file.id}/download`, file.name);
        writeLog(`Скачан файл: ${file.name}`);
      } catch (error) {
        writeLog(error.message, true);
      }
    });

    node.querySelector(".delete-btn").addEventListener("click", async () => {
      try {
        await requestJson(`/api/files/${file.id}`, {
          method: "DELETE",
          headers: csrfHeaders()
        });
        writeLog(`Файл удален: ${file.name}`);
        await loadFiles();
      } catch (error) {
        writeLog(error.message, true);
      }
    });

    const renameInput = node.querySelector(".rename-input");
    renameInput.value = file.name;
    node.querySelector(".rename-btn").addEventListener("click", async () => {
      const newFileName = renameInput.value.trim();
      if (!newFileName) {
        writeLog("Новое имя не может быть пустым.", true);
        return;
      }

      try {
        await requestJson(`/api/files/${file.id}/rename`, {
          method: "PUT",
          headers: {
            ...csrfHeaders(),
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ newFileName })
        });
        writeLog(`Файл переименован: ${newFileName}`);
        await loadFiles();
      } catch (error) {
        writeLog(error.message, true);
      }
    });

    node.querySelector(".create-share-btn").addEventListener("click", async () => {
      try {
        const data = await requestJson(`/api/files/${file.id}/share`, {
          method: "POST",
          headers: csrfHeaders()
        });
        shareUrlInput.value = data.shareUrl || "";
        writeLog("Ссылка создана/получена.");
      } catch (error) {
        writeLog(error.message, true);
      }
    });

    node.querySelector(".disable-share-btn").addEventListener("click", async () => {
      try {
        await requestJson(`/api/files/${file.id}/share`, {
          method: "DELETE",
          headers: csrfHeaders()
        });
        shareUrlInput.value = "";
        writeLog("Ссылка отключена.");
      } catch (error) {
        writeLog(error.message, true);
      }
    });

    const whitelistUserInput = node.querySelector(".whitelist-user-input");
    const whitelistList = node.querySelector(".whitelist-list");

    node.querySelector(".add-whitelist-btn").addEventListener("click", async () => {
      const username = whitelistUserInput.value.trim();
      if (!username) {
        writeLog("Введите логин для whitelist.", true);
        return;
      }

      try {
        await requestJson(`/api/files/${file.id}/whitelist`, {
          method: "POST",
          headers: {
            ...csrfHeaders(),
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ username })
        });
        writeLog(`Пользователь ${username} добавлен в whitelist.`);
        whitelistUserInput.value = "";
        await loadWhitelist(file.id, whitelistList);
      } catch (error) {
        writeLog(error.message, true);
      }
    });

    node.querySelector(".load-whitelist-btn").addEventListener("click", async () => {
      await loadWhitelist(file.id, whitelistList);
    });

    el.filesContainer.appendChild(node);
  }
}

async function loadFiles() {
  try {
    const files = await requestJson("/api/files", {
      method: "GET"
    });
    renderFiles(files);
  } catch (error) {
    el.filesContainer.innerHTML = "";
    if (state.user) {
      writeLog(error.message, true);
    } else {
      el.filesContainer.textContent = "Авторизуйтесь, чтобы увидеть файлы.";
    }
  }
}

async function downloadByShare() {
  const token = tokenFromInput(el.shareInput.value);
  if (!token) {
    writeLog("Введите token или ссылку.", true);
    return;
  }

  try {
    await downloadUrl(`/api/share/${token}`);
    writeLog("Скачивание по ссылке запущено.");
  } catch (error) {
    writeLog(error.message, true);
  }
}

el.registerBtn.addEventListener("click", register);
el.loginBtn.addEventListener("click", login);
el.logoutBtn.addEventListener("click", logout);
el.uploadBtn.addEventListener("click", uploadFile);
el.refreshFilesBtn.addEventListener("click", loadFiles);
el.downloadByShareBtn.addEventListener("click", downloadByShare);

(async () => {
  setAuthInfo();
  await fetchMe();
  await loadFiles();
  writeLog("UI готов.");
})();
