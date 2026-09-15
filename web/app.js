"use strict";

const $ = (id) => document.getElementById(id);
const state = { user: null, messages: [], selected: null, previews: new Map(), view: "inbox", userMode: "create", loading: false, readVersion: 0 };
let noticeTimer;

function showNotice(message, error = false) {
  clearTimeout(noticeTimer);
  $("notice").textContent = message;
  $("notice").classList.toggle("error", error);
  $("notice").hidden = false;
  noticeTimer = setTimeout(() => { $("notice").hidden = true; }, error ? 7000 : 4500);
}

function formError(id, message = "") {
  $(id).textContent = message;
  $(id).hidden = !message;
}

async function api(path, { method = "GET", body, quiet = false } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && state.user) headers["X-CSRF-Token"] = state.user.csrf;
  let response;
  try {
    response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin", cache: "no-store" });
  } catch {
    throw new Error("暂时无法连接服务器，请检查网络后重试。");
  }
  let data;
  try { data = await response.json(); }
  catch { throw new Error("服务器返回了无法读取的响应。"); }
  if (!response.ok || !data.ok) {
    if (response.status === 401 && path !== "/api/login" && !quiet) {
      signedOut();
      showNotice("登录已过期，请重新登录。", true);
    }
    throw new Error(data.error || "请求失败，请稍后重试。");
  }
  return data;
}

function bytes(value) {
  const size = Number(value || 0);
  if (size < 1024) return `${size} B`;
  if (size < 1048576) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1073741824) return `${(size / 1048576).toFixed(1)} MB`;
  return `${(size / 1073741824).toFixed(1)} GB`;
}

function element(tag, className, text) {
  const result = document.createElement(tag);
  if (className) result.className = className;
  if (text !== undefined) result.textContent = text;
  return result;
}

function signedOut() {
  state.user = null;
  state.messages = [];
  state.previews.clear();
  state.selected = null;
  state.readVersion++;
  document.querySelectorAll("dialog[open]").forEach((dialog) => dialog.close());
  $("login-screen").hidden = false;
  $("app-screen").hidden = true;
  $("login-password").value = "";
  $("compose-form").reset();
  $("user-form").reset();
  $("message-list").replaceChildren();
  $("message-body").textContent = "";
  $("message-raw").textContent = "";
  $("login-email").focus();
  document.title = "PostPlus · 邮件，井然有序";
}

async function signedIn(user) {
  state.user = user;
  $("login-screen").hidden = true;
  $("app-screen").hidden = false;
  $("user-address").textContent = user.username;
  $("user-name").textContent = user.username.split("@")[0];
  $("user-avatar").textContent = user.username.slice(0, 1);
  $("nav-admin").hidden = !user.admin;
  $("login-password").value = "";
  await switchView("inbox");
}

async function busy(form, action) {
  const submit = form.querySelector('[type="submit"]');
  submit.disabled = true;
  form.setAttribute("aria-busy", "true");
  try { await action(); }
  finally { submit.disabled = false; form.removeAttribute("aria-busy"); }
}

$("login-form").addEventListener("submit", (event) => {
  event.preventDefault();
  busy(event.currentTarget, async () => {
    formError("login-error");
    try {
      const user = await api("/api/login", { method: "POST", body: { username: $("login-email").value.trim(), password: $("login-password").value } });
      await signedIn(user);
    } catch (error) { formError("login-error", error.message); }
  });
});

$("logout").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); signedOut(); }
  catch (error) { showNotice(error.message, true); }
});

async function switchView(view) {
  state.view = view;
  if (state.user) document.title = `${view === "admin" ? "管理后台" : "收件箱"} · ${state.user.username} · PostPlus`;
  $("inbox-view").hidden = view !== "inbox";
  $("admin-view").hidden = view !== "admin";
  for (const name of ["inbox", "admin"]) {
    $(`nav-${name}`).classList.toggle("active", view === name);
    if (view === name) $(`nav-${name}`).setAttribute("aria-current", "page");
    else $(`nav-${name}`).removeAttribute("aria-current");
  }
  if (view === "inbox") await loadInbox();
  else await loadAdmin();
}

$("nav-inbox").addEventListener("click", () => switchView("inbox"));
$("nav-admin").addEventListener("click", () => switchView("admin"));
$("refresh").addEventListener("click", loadInbox);
$("admin-refresh").addEventListener("click", loadAdmin);

function renderMessages() {
  const fragment = document.createDocumentFragment();
  state.messages.slice().reverse().forEach((message) => {
    const id = String(message.id);
    const preview = state.previews.get(id) || message;
    const button = element("button", "message-row");
    button.type = "button";
    button.classList.toggle("seen", Boolean(message.seen));
    button.classList.toggle("selected", state.selected === id);
    button.setAttribute("aria-pressed", String(state.selected === id));
    const title = preview?.subject || `邮件 #${message.uid}`;
    button.setAttribute("aria-label", `${message.seen ? "" : "未读，"}${title}`);
    const avatar = element("span", "avatar", preview?.from?.slice(0, 1) || "✉");
    avatar.setAttribute("aria-hidden", "true");
    const copy = element("span", "message-row-copy");
    copy.append(element("span", "message-row-title", title));
    copy.append(element("span", "message-row-subtitle", preview?.from || `${bytes(message.size)} · ${message.seen ? "已读" : "未读"}`));
    const dot = element("span", "message-dot");
    dot.setAttribute("aria-hidden", "true");
    button.append(avatar, copy, dot);
    button.addEventListener("click", () => openMessage(id));
    fragment.append(button);
  });
  $("message-list").replaceChildren(fragment);
  $("message-total").textContent = `${state.messages.length} 封`;
  $("inbox-count").textContent = String(state.messages.filter((message) => !message.seen).length);
  $("empty-mail").hidden = state.messages.length !== 0;
}

function clearReader() {
  state.selected = null;
  state.readVersion++;
  $("reader-content").hidden = true;
  $("reader-placeholder").hidden = false;
  document.querySelector(".mail-workspace").classList.remove("reading");
}

async function loadInbox() {
  if (state.loading || !state.user) return;
  state.loading = true;
  $("refresh").disabled = true;
  $("message-list").setAttribute("aria-busy", "true");
  $("mail-status").textContent = "正在同步…";
  const user = state.user;
  try {
    const data = await api("/api/messages");
    if (state.user !== user) return;
    state.messages = data.messages;
    if (!state.selected || !state.messages.some((message) => String(message.id) === state.selected)) clearReader();
    renderMessages();
    $("mail-status").textContent = `更新于 ${new Date().toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" })}`;
    if (state.view === "inbox") document.title = `收件箱 · ${user.username} · PostPlus`;
  } catch (error) {
    $("mail-status").textContent = "同步失败";
    showNotice(error.message, true);
  } finally {
    state.loading = false;
    $("refresh").disabled = false;
    $("message-list").removeAttribute("aria-busy");
  }
}

async function openMessage(id) {
  const version = ++state.readVersion;
  $("reader").setAttribute("aria-busy", "true");
  try {
    const data = await api(`/api/messages/${encodeURIComponent(id)}`);
    if (version !== state.readVersion || !state.user) return;
    state.selected = id;
    const preview = data.message || {};
    state.previews.set(id, preview);
    const message = state.messages.find((item) => String(item.id) === id);
    if (message) message.seen = true;
    $("message-subject").textContent = preview.subject || "（无主题）";
    $("message-from").textContent = preview.from || "—";
    $("message-to").textContent = preview.to || state.user.username;
    $("message-date").textContent = preview.date || "—";
    $("message-body").textContent = preview.text || "（空白邮件）";
    $("message-raw").textContent = data.raw || "";
    document.querySelector(".raw-message").open = false;
    $("reader-placeholder").hidden = true;
    $("reader-content").hidden = false;
    document.querySelector(".mail-workspace").classList.add("reading");
    $("reader").scrollTop = 0;
    renderMessages();
    $("message-subject").focus({ preventScroll: true });
  } catch (error) { showNotice(error.message, true); }
  finally { if (version === state.readVersion) $("reader").removeAttribute("aria-busy"); }
}

$("reader-back").addEventListener("click", () => {
  document.querySelector(".mail-workspace").classList.remove("reading");
  document.querySelector('.message-row[aria-pressed="true"]')?.focus();
});

$("compose-open").addEventListener("click", () => {
  formError("compose-error");
  $("compose-dialog").showModal();
});

$("compose-form").addEventListener("submit", (event) => {
  event.preventDefault();
  busy(event.currentTarget, async () => {
    formError("compose-error");
    const recipients = $("compose-to").value.split(/[,;，；\n]/).map((value) => value.trim()).filter(Boolean);
    if (!recipients.length) { formError("compose-error", "请填写至少一个收件人邮箱。"); return; }
    try {
      await api("/api/send", { method: "POST", body: { to: recipients, subject: $("compose-subject").value, text: $("compose-text").value } });
      $("compose-dialog").close();
      $("compose-form").reset();
      showNotice("邮件已加入投递队列。");
      await loadInbox();
    } catch (error) { formError("compose-error", error.message); }
  });
});

$("message-delete").addEventListener("click", () => {
  if (!state.selected) return;
  formError("delete-error");
  $("delete-dialog").showModal();
});

$("delete-form").addEventListener("submit", (event) => {
  event.preventDefault();
  busy(event.currentTarget, async () => {
    if (!state.selected) return;
    formError("delete-error");
    try {
      await api(`/api/messages/${encodeURIComponent(state.selected)}`, { method: "DELETE" });
      state.previews.delete(state.selected);
      clearReader();
      $("delete-dialog").close();
      showNotice("邮件已删除。");
      await loadInbox();
    } catch (error) { formError("delete-error", error.message); }
  });
});

async function loadAdmin() {
  if (!state.user?.admin) return;
  const user = state.user;
  $("admin-refresh").disabled = true;
  try {
    const results = await Promise.allSettled([api("/api/admin/stats"), api("/api/admin/users"), api("/api/admin/queue")]);
    if (user !== state.user) return;
    if (results[0].status === "fulfilled") {
      const stats = results[0].value;
      $("stat-messages").textContent = Number(stats.messages).toLocaleString();
      $("stat-queued").textContent = Number(stats.queued).toLocaleString();
      $("stat-bytes").textContent = bytes(stats.bytes);
    } else {
      ["stat-messages", "stat-queued", "stat-bytes"].forEach((id) => { $(id).textContent = "—"; });
      showNotice(results[0].reason.message, true);
    }
    if (results[1].status === "fulfilled") {
      const fragment = document.createDocumentFragment();
      results[1].value.users.forEach((account) => {
        const row = element("tr");
        const email = element("td", "", account.username);
        const role = element("td");
        role.append(element("span", account.admin ? "role-badge admin" : "role-badge", account.admin ? "管理员" : "普通用户"));
        const actions = element("td");
        const button = element("button", "table-action", "重置密码");
        button.type = "button";
        button.setAttribute("aria-label", `重置 ${account.username} 的密码`);
        button.addEventListener("click", () => openUserDialog(account.username));
        actions.append(button);
        row.append(email, role, actions);
        fragment.append(row);
      });
      $("users-body").replaceChildren(fragment);
    } else {
      $("users-body").replaceChildren();
      showNotice(results[1].reason.message, true);
    }
    if (results[2].status === "fulfilled") {
      const fragment = document.createDocumentFragment();
      results[2].value.jobs.forEach((job) => {
        const row = element("tr");
        row.append(element("td", "", job.recipient), element("td", "", job.state === "pending" ? "等待投递" : "已隔离"),
          element("td", "", String(job.attempts)), element("td", "", job.error || "—"));
        fragment.append(row);
      });
      $("queue-body").replaceChildren(fragment);
      $("queue-empty").hidden = results[2].value.jobs.length !== 0;
    } else {
      $("queue-body").replaceChildren();
      $("queue-empty").hidden = true;
      showNotice(results[2].reason.message, true);
    }
  } finally { $("admin-refresh").disabled = false; }
}

function openUserDialog(username = "") {
  state.userMode = username ? "password" : "create";
  $("user-form").reset();
  formError("user-error");
  $("user-dialog-title").textContent = username ? "重置密码" : "新建用户";
  $("new-email").value = username;
  $("new-email").readOnly = Boolean(username);
  $("admin-checkbox-label").hidden = Boolean(username);
  $("user-dialog").showModal();
}

$("user-create-open").addEventListener("click", () => openUserDialog());
$("user-form").addEventListener("submit", (event) => {
  event.preventDefault();
  busy(event.currentTarget, async () => {
    formError("user-error");
    const username = $("new-email").value.trim().toLowerCase();
    const password = $("new-password").value;
    const changing = state.userMode === "password";
    const currentAccount = username === state.user?.username;
    try {
      await api(changing ? "/api/admin/password" : "/api/admin/users", { method: "POST", body: { username, password, admin: $("new-admin").checked } });
      $("user-dialog").close();
      $("new-password").value = "";
      if (changing && currentAccount) {
        signedOut();
        showNotice("密码已更新，请使用新密码登录。");
      } else {
        showNotice(changing ? "密码已更新，该用户的登录会话已失效。" : "用户账号已创建。");
        await loadAdmin();
      }
    } catch (error) { formError("user-error", error.message); }
  });
});

document.querySelectorAll("[data-close]").forEach((button) => {
  button.addEventListener("click", () => $(button.dataset.close).close());
});
$("user-dialog").addEventListener("close", () => { $("new-password").value = ""; });

(async () => {
  try { await signedIn(await api("/api/session", { quiet: true })); }
  catch { $("login-email").focus(); }
})();
