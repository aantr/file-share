const state = {
  csrfToken: sessionStorage.getItem("fs_csrf") || "",
  user: null,
  lastKnownEmail: ""
};
const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;

const el = {
  loginUsername: document.getElementById("loginUsername"),
  loginPassword: document.getElementById("loginPassword"),
  registerUsername: document.getElementById("registerUsername"),
  registerEmail: document.getElementById("registerEmail"),
  registerPassword: document.getElementById("registerPassword"),
  currentPassword: document.getElementById("currentPassword"),
  newPassword: document.getElementById("newPassword"),
  recoveryEmail: document.getElementById("recoveryEmail"),
  resetToken: document.getElementById("resetToken"),
  resetNewPassword: document.getElementById("resetNewPassword"),
  registerBtn: document.getElementById("registerBtn"),
  loginBtn: document.getElementById("loginBtn"),
  logoutBtn: document.getElementById("logoutBtn"),
  changePasswordBtn: document.getElementById("changePasswordBtn"),
  forgotPasswordBtn: document.getElementById("forgotPasswordBtn"),
  resetPasswordBtn: document.getElementById("resetPasswordBtn"),
  authInfo: document.getElementById("authInfo"),
  uploadFileInput: document.getElementById("uploadFileInput"),
  uploadBtn: document.getElementById("uploadBtn"),
  refreshFilesBtn: document.getElementById("refreshFilesBtn"),
  filesContainer: document.getElementById("filesContainer"),
  shareInput: document.getElementById("shareInput"),
  downloadByShareBtn: document.getElementById("downloadByShareBtn"),
  tabButtons: document.querySelectorAll(".tab-btn"),
  tabPanels: document.querySelectorAll(".tab-panel"),
  subtabButtons: document.querySelectorAll(".subtab-btn"),
  subtabPanels: document.querySelectorAll(".subtab-panel"),
  messageBox: document.getElementById("messageBox"),
  log: document.getElementById("log"),
  fileTemplate: document.getElementById("fileTemplate")
};

let messageTimer = null;

function showMessage(message, kind) {
  if (!el.messageBox) return;
  el.messageBox.textContent = message;
  el.messageBox.classList.remove("hidden");
  el.messageBox.classList.remove("error", "success");
  el.messageBox.classList.add(kind);

  if (messageTimer) {
    clearTimeout(messageTimer);
  }
  messageTimer = setTimeout(() => {
    el.messageBox.classList.add("hidden");
    el.messageBox.textContent = "";
  }, 6000);
}

function showError(message) {
  showMessage(message, "error");
}

function showSuccess(message) {
  showMessage(message, "success");
}

function writeLog(message, isError = false) {
  const prefix = new Date().toLocaleTimeString();
  const line = `[${prefix}] ${isError ? "ERROR: " : ""}${message}\n`;
  el.log.textContent = line + el.log.textContent;
  if (isError) {
    showError(message);
  }
}

function notifySuccess(message) {
  writeLog(message, false);
  showSuccess(message);
}

function setupTabs() {
  if (!el.tabButtons.length || !el.tabPanels.length) return;

  for (const button of el.tabButtons) {
    button.addEventListener("click", () => {
      const targetId = button.dataset.tabTarget;
      if (!targetId) return;

      for (const panel of el.tabPanels) {
        panel.classList.toggle("active", panel.id === targetId);
      }

      for (const tabButton of el.tabButtons) {
        tabButton.classList.toggle("active", tabButton === button);
      }
    });
  }
}

function setupAccountSubtabs() {
  if (!el.subtabButtons.length || !el.subtabPanels.length) return;

  for (const button of el.subtabButtons) {
    button.addEventListener("click", () => {
      const targetId = button.dataset.subtabTarget;
      if (!targetId) return;

      for (const panel of el.subtabPanels) {
        panel.classList.toggle("active", panel.id === targetId);
      }

      for (const subtabButton of el.subtabButtons) {
        subtabButton.classList.toggle("active", subtabButton === button);
      }
    });
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
    const message = getFriendlyApiErrorMessage(url, response.status, payload);
    throw new Error(message);
  }
  return payload;
}

function getFriendlyApiErrorMessage(url, status, payload) {
  const serverMessage = payload?.error || payload?.message;
  if (serverMessage) {
    return serverMessage;
  }

  if (status === 401) {
    if (url.includes("/api/auth/login")) {
      return "Неверный логин или пароль. Проверьте данные и попробуйте снова.";
    }
    return "Сессия истекла или вы не авторизованы. Войдите снова.";
  }

  if (status === 403) {
    return "Доступ запрещен. У вас нет прав для этого действия.";
  }

  if (status === 404) {
    return "Ресурс не найден. Возможно, он уже удален.";
  }

  if (status >= 500) {
    return "Ошибка сервера. Попробуйте еще раз через несколько секунд.";
  }

  return `Ошибка запроса (HTTP ${status}).`;
}

function isValidEmail(email) {
  if (!email) return false;
  const atPos = email.indexOf("@");
  const dotPos = email.lastIndexOf(".");
  return atPos > 0 && dotPos > atPos + 1 && dotPos < email.length - 1;
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
    const emailPart = state.user.email ? ` (${state.user.email})` : "";
    el.authInfo.textContent = `Авторизован: ${state.user.username}${emailPart}`;
  } else {
    el.authInfo.textContent = "Не авторизован";
  }
}

async function fetchMe() {
  try {
    const data = await requestJson("/api/auth/me", {
      method: "GET"
    });
    state.user = { id: data.id, username: data.username, email: data.email || "" };
    state.lastKnownEmail = data.email || state.lastKnownEmail;
    setCsrfToken(data.csrfToken || "");
    if (data.email) {
      el.recoveryEmail.value = data.email;
      el.registerEmail.value = data.email;
    }
    setAuthInfo();
  } catch {
    state.user = null;
    setCsrfToken("");
    setAuthInfo();
  }
}

async function register() {
  const username = el.registerUsername.value.trim();
  const email = el.registerEmail.value.trim();
  const password = el.registerPassword.value;
  if (!username || !email || !password) {
    writeLog("Введите логин, email и пароль.", true);
    return;
  }
  if (!isValidEmail(email)) {
    writeLog("Введите корректный email.", true);
    return;
  }

  try {
    await requestJson("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email, password })
    });
    notifySuccess(`Пользователь ${username} зарегистрирован.`);
    el.loginUsername.value = username;
    el.loginPassword.value = "";
  } catch (error) {
    writeLog(error.message, true);
  }
}

async function login() {
  const username = el.loginUsername.value.trim();
  const password = el.loginPassword.value;

  try {
    const data = await requestJson("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    setCsrfToken(data.csrfToken || "");
    state.user = data.user;
    if (state.user?.email) {
      state.lastKnownEmail = state.user.email;
      el.recoveryEmail.value = state.user.email;
      el.registerEmail.value = state.user.email;
    }
    setAuthInfo();
    notifySuccess(`Вход выполнен: ${state.user.username}`);
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
    notifySuccess("Выход выполнен.");
  } catch (error) {
    writeLog(error.message || "Не удалось выполнить выход.", true);
  }
}

async function changePassword() {
  const currentPassword = el.currentPassword.value;
  const newPassword = el.newPassword.value;

  if (!currentPassword || !newPassword) {
    writeLog("Введите текущий и новый пароль.", true);
    return;
  }

  try {
    await requestJson("/api/auth/change-password", {
      method: "POST",
      headers: {
        ...csrfHeaders(),
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ currentPassword, newPassword })
    });
    el.currentPassword.value = "";
    el.newPassword.value = "";
    notifySuccess("Пароль успешно изменен.");
  } catch (error) {
    writeLog(error.message, true);
  }
}

async function forgotPassword() {
  const email = (el.recoveryEmail.value || state.lastKnownEmail || el.registerEmail.value || "").trim();
  if (!email) {
    writeLog("Введите email для восстановления.", true);
    return;
  }
  if (!isValidEmail(email)) {
    writeLog("Введите корректный email.", true);
    return;
  }

  try {
    const data = await requestJson("/api/auth/forgot-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ email })
    });
    if (data?.resetToken) {
      el.resetToken.value = data.resetToken;
      alert(`Demo email: токен восстановления\n${data.resetToken}`);
    }
    notifySuccess("Инструкция по восстановлению отправлена.");
  } catch (error) {
    writeLog(error.message, true);
  }
}

async function resetPassword() {
  const email = (el.recoveryEmail.value || state.lastKnownEmail || el.registerEmail.value || "").trim();
  const resetToken = el.resetToken.value.trim();
  const newPassword = el.resetNewPassword.value;

  if (!email || !resetToken || !newPassword) {
    writeLog("Введите email, токен и новый пароль.", true);
    return;
  }
  if (!isValidEmail(email)) {
    writeLog("Введите корректный email.", true);
    return;
  }

  try {
    await requestJson("/api/auth/reset-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ email, resetToken, newPassword })
    });
    el.resetNewPassword.value = "";
    notifySuccess("Пароль восстановлен. Теперь можно войти с новым паролем.");
  } catch (error) {
    writeLog(error.message, true);
  }
}

async function uploadFile() {
  const file = el.uploadFileInput.files?.[0];
  if (!file) {
    writeLog("Выберите файл для загрузки.", true);
    return;
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    writeLog(`Файл слишком большой. Максимум ${Math.floor(MAX_UPLOAD_BYTES / (1024 * 1024))} MB.`, true);
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
    let payload = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    if (!response.ok) {
      throw new Error(payload?.error || `HTTP ${response.status}`);
    }

    notifySuccess(`Файл загружен: ${payload.file?.name || file.name}`);
    el.uploadFileInput.value = "";
    await loadFiles();
  } catch (error) {
    if (error instanceof TypeError) {
      writeLog("Не удалось отправить файл. Проверьте размер и доступность сервера.", true);
      return;
    }
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

async function getWhitelist(fileId) {
  return await requestJson(`/api/files/${fileId}/whitelist`, {
    method: "GET"
  });
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
        notifySuccess(`Скачан файл: ${file.name}`);
      } catch (error) {
        writeLog(error.message, true);
      }
    });

    node.querySelector(".delete-btn").addEventListener("click", async () => {
      if (!confirm(`Удалить файл "${file.name}"?`)) {
        return;
      }

      try {
        await requestJson(`/api/files/${file.id}`, {
          method: "DELETE",
          headers: csrfHeaders()
        });
        notifySuccess(`Файл удален: ${file.name}`);
        await loadFiles();
      } catch (error) {
        writeLog(error.message, true);
      }
    });

    node.querySelector(".rename-btn").addEventListener("click", async () => {
      const newFileName = prompt("Введите новое имя файла:", file.name)?.trim() || "";
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
        notifySuccess(`Файл переименован: ${newFileName}`);
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
        notifySuccess("Ссылка создана/получена.");
        alert(`Ссылка на файл:\n${shareUrlInput.value}`);
      } catch (error) {
        writeLog(error.message, true);
      }
    });

    node.querySelector(".disable-share-btn").addEventListener("click", async () => {
      if (!confirm("Отключить ссылку на этот файл?")) {
        return;
      }

      try {
        await requestJson(`/api/files/${file.id}/share`, {
          method: "DELETE",
          headers: csrfHeaders()
        });
        shareUrlInput.value = "";
        notifySuccess("Ссылка отключена.");
      } catch (error) {
        writeLog(error.message, true);
      }
    });

    node.querySelector(".add-whitelist-btn").addEventListener("click", async () => {
      const username = prompt("Введите логин пользователя для whitelist:")?.trim() || "";
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
        notifySuccess(`Пользователь ${username} добавлен в whitelist.`);
      } catch (error) {
        writeLog(error.message, true);
      }
    });

    node.querySelector(".copy-link-btn").addEventListener("click", async () => {
      if (!shareUrlInput.value) {
        writeLog("Ссылка еще не создана.", true);
        return;
      }

      try {
        await navigator.clipboard.writeText(shareUrlInput.value);
        notifySuccess("Ссылка скопирована в буфер.");
      } catch {
        writeLog("Не удалось скопировать ссылку.", true);
      }
    });

    node.querySelector(".load-whitelist-btn").addEventListener("click", async () => {
      try {
        const users = await getWhitelist(file.id);
        if (!Array.isArray(users) || users.length === 0) {
          alert("Белый список пуст.");
          return;
        }
        alert(`Whitelist:\n- ${users.join("\n- ")}`);
      } catch (error) {
        writeLog(error.message, true);
      }
    });

    node.querySelector(".remove-whitelist-btn").addEventListener("click", async () => {
      const username = prompt("Введите логин пользователя, которого нужно удалить из whitelist:")?.trim() || "";
      if (!username) {
        writeLog("Логин не введен.", true);
        return;
      }

      try {
        await requestJson(`/api/files/${file.id}/whitelist/${encodeURIComponent(username)}`, {
          method: "DELETE",
          headers: csrfHeaders()
        });
        notifySuccess(`Пользователь ${username} удален из whitelist.`);
      } catch (error) {
        writeLog(error.message, true);
      }
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
    notifySuccess("Скачивание по ссылке запущено.");
  } catch (error) {
    writeLog(error.message, true);
  }
}

el.registerBtn.addEventListener("click", register);
el.loginBtn.addEventListener("click", login);
el.logoutBtn.addEventListener("click", logout);
el.changePasswordBtn.addEventListener("click", changePassword);
el.forgotPasswordBtn.addEventListener("click", forgotPassword);
el.resetPasswordBtn.addEventListener("click", resetPassword);
el.uploadBtn.addEventListener("click", uploadFile);
el.refreshFilesBtn.addEventListener("click", loadFiles);
el.downloadByShareBtn.addEventListener("click", downloadByShare);

(async () => {
  setupTabs();
  setupAccountSubtabs();
  setAuthInfo();
  await fetchMe();
  await loadFiles();
  writeLog("UI готов.");
})();
