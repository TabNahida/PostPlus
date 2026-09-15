"use strict";

const t = (...args) => PostPlusI18n.t(...args);
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
    throw new Error(t("Cannot connect to the server. Check your connection and try again."));
  }
  let data;
  try { data = await response.json(); }
  catch { throw new Error(t("The server returned an unreadable response.")); }
  if (!response.ok || !data.ok) {
    if (response.status === 401 && path !== "/api/login" && !quiet) {
      signedOut();
      showNotice(t("Your session has expired. Please sign in again."), true);
    }
    throw new Error(PostPlusI18n.error(data));
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
  for (const id of ["users-body", "queue-body", "logs-body"]) $(id).replaceChildren();
  logData = null;
  logVersion++;
  $("login-email").focus();
  document.title = t("PostPlus · Your mail, in order");
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
  if (state.user) document.title = `${t(view === "admin" ? "Administration" : "Inbox")} · ${state.user.username} · PostPlus`;
  $("inbox-view").hidden = view !== "inbox";
  $("admin-view").hidden = view !== "admin";
  for (const name of ["inbox", "admin"]) {
    $(`nav-${name}`).classList.toggle("active", view === name);
    if (view === name) $(`nav-${name}`).setAttribute("aria-current", "page");
    else $(`nav-${name}`).removeAttribute("aria-current");
  }
  if (view === "inbox") await loadInbox();
  else { await loadAdmin(); await loadLogs(); }
}

$("nav-inbox").addEventListener("click", () => switchView("inbox"));
$("nav-admin").addEventListener("click", () => switchView("admin"));
$("refresh").addEventListener("click", loadInbox);
$("admin-refresh").addEventListener("click", () => { loadAdmin(); loadLogs(); });

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
    const title = preview?.subject || t("Message #{id}", {id: message.uid});
    button.setAttribute("aria-label", message.seen ? title : t("Unread, {title}", {title}));
    const avatar = element("span", "avatar", preview?.from?.slice(0, 1) || "✉");
    avatar.setAttribute("aria-hidden", "true");
    const copy = element("span", "message-row-copy");
    copy.append(element("span", "message-row-title", title));
    copy.append(element("span", "message-row-subtitle", preview?.from || `${bytes(message.size)} · ${t(message.seen ? "Read" : "Unread")}`));
    const dot = element("span", "message-dot");
    dot.setAttribute("aria-hidden", "true");
    button.append(avatar, copy, dot);
    button.addEventListener("click", () => openMessage(id));
    fragment.append(button);
  });
  $("message-list").replaceChildren(fragment);
  $("message-total").textContent = t(state.messages.length === 1 ? "{count} message" : "{count} messages", {count: state.messages.length});
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
  $("mail-status").textContent = t("Syncing…");
  const user = state.user;
  try {
    const data = await api("/api/messages");
    if (state.user !== user) return;
    state.messages = data.messages;
    if (!state.selected || !state.messages.some((message) => String(message.id) === state.selected)) clearReader();
    renderMessages();
    $("mail-status").textContent = t("Updated at {time}", {time: new Date().toLocaleTimeString(PostPlusI18n.language, { hour: "2-digit", minute: "2-digit" })});
    if (state.view === "inbox") document.title = `${t("Inbox")} · ${user.username} · PostPlus`;
  } catch (error) {
    $("mail-status").textContent = t("Sync failed");
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
    $("message-subject").textContent = preview.subject || t("(No subject)");
    $("message-from").textContent = preview.from || "—";
    $("message-to").textContent = preview.to || state.user.username;
    $("message-date").textContent = preview.date || "—";
    $("message-body").textContent = preview.text || t("(Empty message)");
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
    if (!recipients.length) { formError("compose-error", t("Enter at least one recipient email address.")); return; }
    try {
      await api("/api/send", { method: "POST", body: { to: recipients, subject: $("compose-subject").value, text: $("compose-text").value } });
      $("compose-dialog").close();
      $("compose-form").reset();
      showNotice(t("Your message has been queued for delivery."));
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
      showNotice(t("Message deleted."));
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
      $("stat-messages").textContent = Number(stats.messages).toLocaleString(PostPlusI18n.language);
      $("stat-queued").textContent = Number(stats.queued).toLocaleString(PostPlusI18n.language);
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
        role.append(element("span", account.admin ? "role-badge admin" : "role-badge", t(account.admin ? "Administrator" : "User")));
        const actions = element("td");
        const button = element("button", "table-action", t("Reset password"));
        button.type = "button";
        button.setAttribute("aria-label", t("Reset password for {username}", {username: account.username}));
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
        row.append(element("td", "", job.recipient), element("td", "", t(job.state === "pending" ? "Pending" : "Quarantined")),
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
  $("user-dialog-title").textContent = username ? t("Reset password") : t("Create user");
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
        showNotice(t("Password updated. Sign in with your new password."));
      } else {
        showNotice(changing ? t("Password updated. This user's sessions have been revoked.") : t("User account created."));
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


let logVersion = 0;
let logData = null;
function renderLogs() {
  if (!logData) return;
  const selected = $("logs-service").value;
  const all = element("option", "", t("All services"));
  all.value = "";
  $("logs-service").replaceChildren(all);
  const services = [...new Set([...(logData.services || []), ...(selected ? [selected] : [])])].sort();
  services.forEach(service => {
    const option = element("option", "", service);
    option.value = service;
    $("logs-service").append(option);
  });
  $("logs-service").value = selected;
  const fragment = document.createDocumentFragment();
  (logData.entries || []).forEach(entry => {
    const row = element("tr");
    const level = {debug:"Debug",info:"Info",warn:"Warning",warning:"Warning",error:"Error"}[entry.level] || entry.level;
    row.append(element("td", "log-time", entry.timestamp), element("td", "", entry.service),
      element("td", "", t(level)), element("td", "", String(entry.pid ?? "")), element("td", "log-message", entry.message));
    fragment.append(row);
  });
  $("logs-body").replaceChildren(fragment);
  $("logs-empty").hidden = Boolean(logData.entries?.length);
  $("logs-status").textContent = t(logData.truncated ? "Showing {count} recent events. Older events are omitted." : "Showing {count} recent events.", {count: logData.entries?.length || 0});
}
async function loadLogs() {
  if (!state.user?.admin) return;
  const user = state.user;
  const version = ++logVersion;
  const query = new URLSearchParams({limit:"100"});
  if ($("logs-service").value) query.set("service", $("logs-service").value);
  if ($("logs-level").value) query.set("level", $("logs-level").value);
  $("logs-refresh").disabled = true;
  $("logs-body").setAttribute("aria-busy", "true");
  $("logs-status").textContent = t("Loading logs…");
  formError("logs-error");
  try {
    const result = await api(`/api/admin/logs?${query}`);
    if (version !== logVersion || user !== state.user) return;
    logData = result;
    renderLogs();
  } catch (error) {
    if (version !== logVersion || user !== state.user) return;
    logData = null;
    $("logs-body").replaceChildren();
    $("logs-empty").hidden = true;
    $("logs-status").textContent = "";
    formError("logs-error", error.message);
  } finally {
    if (version === logVersion) {
      $("logs-refresh").disabled = false;
      $("logs-body").removeAttribute("aria-busy");
    }
  }
}
$("logs-refresh").addEventListener("click", loadLogs);
$("logs-service").addEventListener("change", loadLogs);
$("logs-level").addEventListener("change", loadLogs);
document.addEventListener("postplus:language", () => {
  document.title = state.user ? `${t(state.view === "admin" ? "Administration" : "Inbox")} · ${state.user.username} · PostPlus` : t("PostPlus · Your mail, in order");
  $("notice").hidden = true;
  for (const id of ["login-error", "compose-error", "user-error", "delete-error", "logs-error"]) formError(id);
  $("user-dialog-title").textContent = t(state.userMode === "password" ? "Reset password" : "Create user");
  $("mail-status").textContent = t(state.loading ? "Syncing…" : "Ready");
  renderMessages();
  if (state.selected) {
    const preview = state.previews.get(state.selected) || {};
    $("message-subject").textContent = preview.subject || t("(No subject)");
    $("message-body").textContent = preview.text || t("(Empty message)");
  }
  if (state.user?.admin && state.view === "admin") { loadAdmin(); renderLogs(); }
});
document.title = t("PostPlus · Your mail, in order");
$("mail-status").textContent = t("Ready");
$("message-total").textContent = t("{count} messages", {count:0});
