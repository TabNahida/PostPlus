"use strict";
const t = (...args) => PostPlusI18n.t(...args);
const $ = id => document.getElementById(id);
const state = {user:null,view:"overview",userMode:"create"};
const viewLabels = {overview:"Overview",accounts:"User accounts",queue:"Delivery queue",logs:"Service logs",settings:"Server settings"};
let settingsData = null;
let settingsEditor = null;
let settingsLoading = false;
let settingsSaving = false;
let acmeControl=null;
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
    const error = new Error(PostPlusI18n.error(data));
    error.field = data.field;
    throw error;
  }
  return data;
}

function bytes(value) { return PostPlusSize.format(value); }

function element(tag, className, text) {
  const result = document.createElement(tag);
  if (className) result.className = className;
  if (text !== undefined) result.textContent = text;
  return result;
}


function signedOut() {
  state.user = null;
  document.querySelectorAll("dialog[open]").forEach(dialog => dialog.close());
  $("login-screen").hidden = false;
  $("app-screen").hidden = true;
  $("login-password").value = "";
  $("user-form").reset();
  for (const id of ["users-body", "queue-body", "logs-body", "settings-fields"]) $(id).replaceChildren();
  logData = null;
  logVersion++;
  settingsData = null;
  settingsEditor = null;
  acmeControl?.dispose();acmeControl=null;$("admin-acme").replaceChildren();
  clearInspection();
  quotaUsername="";
  $("login-email").focus();
  document.title = t("PostPlus · Administration");
}
async function signedIn(user) {
  if (!user.admin) throw new Error(t("Administrator access is required."));
  state.user = user;
  $("login-screen").hidden = true;
  $("app-screen").hidden = false;
  $("settings-success").hidden = true;
  $("user-address").textContent = user.username;
  $("user-name").textContent = user.username.split("@")[0];
  $("user-avatar").textContent = user.username.slice(0,1);
  $("login-password").value = "";
  await switchView("overview");
  await loadSettings();
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
  if (!Object.hasOwn(viewLabels,view)) return;
  state.view = view;
  $("view-title").textContent = t(viewLabels[view]);
  document.title = `${t(viewLabels[view])} · PostPlus`;
  for (const name of Object.keys(viewLabels)) {
    $(`view-${name}`).hidden = name !== view;
    $(`nav-${name}`).classList.toggle("active",name === view);
    if (name === view) $(`nav-${name}`).setAttribute("aria-current","page");
    else $(`nav-${name}`).removeAttribute("aria-current");
  }
  $("admin-refresh").hidden = view === "settings";
  if (view === "logs") await loadLogs();
  else if (view === "settings") { if (!settingsData) await loadSettings(); }
  else await loadAdmin();
}
document.querySelectorAll("[data-view]").forEach(button => button.addEventListener("click", () => switchView(button.dataset.view)));
$("admin-refresh").addEventListener("click", () => state.view === "logs" ? loadLogs() : loadAdmin());
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
        const inspect = element("button","table-action",t("Inspect mail"));
        inspect.type="button";inspect.addEventListener("click",()=>openInspection(account.username));
        const quota = element("button","table-action",t("Storage quota"));
        quota.type="button";quota.addEventListener("click",()=>openQuota(account.username));
        actions.classList.add("account-actions");
        actions.append(inspect,quota,button);
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

function setLink(id, value) {
  const destination = new URL(value);
  if (!["http:","https:"].includes(destination.protocol) || destination.username || destination.password) throw new Error(t("The server returned an unreadable response."));
  $(id).href = destination.href;
}
async function loadSettings() {
  if (!state.user?.admin || settingsLoading) return;
  const user = state.user;
  settingsLoading = true;
  $("settings-loading").hidden = false;
  formError("settings-error");
  try {
    const data = await api("/api/admin/config");
    if (state.user !== user) return;
    settingsData = data;
    if (!acmeControl) acmeControl=PostPlusAcme.create($("admin-acme"),{request:(path,options)=>api("/api/admin/acme"+path,options),domain:data.values.domain,prefix:"admin-acme",onCertificate:async paths=>{if($("settings-form").hidden)await loadSettings();if(!settingsEditor || $("settings-form").hidden)throw new Error(t("Load server settings before applying certificate paths."));for(const [key,value] of Object.entries(paths)){const input=$("config-"+key);if(input){input.value=value;input.closest("details").open=true;}}}});
    $("settings-pending").hidden = !data.restart_required;
    settingsEditor = PostPlusSettings.create($("settings-fields"),data.schema,data.values,{prefix:"config",secretStatus:data.secret_status});
    $("settings-success").hidden = true;
    $("settings-form").hidden = false;
    setLink("open-webmail",data.web_url);
    $("server-links").hidden = false;
  } catch (error) { formError("settings-error",error.message); settingsEditor?.highlight(error.field); }
  finally { settingsLoading = false; $("settings-loading").hidden = true; }
}
$("settings-edit").addEventListener("click",loadSettings);
$("settings-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (settingsSaving || !settingsEditor) return;
  formError("settings-error");
  let values;
  try { values = settingsEditor.read(); }
  catch (error) { formError("settings-error",error.message); return; }
  if (!Object.keys(values).length) { showNotice(t("No settings have changed.")); return; }
  settingsSaving = true;
  $("settings-save").disabled = true;
  $("settings-form").setAttribute("aria-busy","true");
  try {
    const data = await api("/api/admin/config",{method:"POST",body:{revision:settingsData.revision,values}});
    $("settings-pending").hidden = !data.restart_required;
    setLink("settings-open-admin",data.admin_url);
    setLink("settings-open-web",data.web_url);
    settingsEditor.clearSecrets();
    $("settings-form").hidden = true;
    $("settings-success").hidden = false;
    $("settings-success").scrollIntoView({block:"center"});
  } catch (error) { formError("settings-error",error.message); settingsEditor?.highlight(error.field); }
  finally { settingsSaving = false; $("settings-save").disabled = false; $("settings-form").removeAttribute("aria-busy"); }
});
document.addEventListener("postplus:language", () => {
  document.title = state.user ? `${t(viewLabels[state.view])} · PostPlus` : t("PostPlus · Administration");
  $("view-title").textContent = t(viewLabels[state.view]);
  $("notice").hidden = true;
  for (const id of ["login-error","user-error","logs-error","settings-error"]) formError(id);
  $("user-dialog-title").textContent = t(state.userMode === "password" ? "Reset password" : "Create user");
  settingsEditor?.translate();
  acmeControl?.translate();
  renderInspection();
  if (state.user) { loadAdmin(); renderLogs(); }
});

const mailFolderLabels={INBOX:"Inbox",Sent:"Sent",Drafts:"Drafts",Trash:"Trash",Junk:"Junk",Archive:"Archive"};
let inspectUsername="",inspectVersion=0,inspectReadVersion=0,inspectMessages=[],inspectSelected=null;
let quotaUsername="",quotaControl=null;
function clearInspection() {
  inspectUsername="";inspectVersion++;inspectReadVersion++;inspectMessages=[];inspectSelected=null;
  $("inspect-messages").replaceChildren();$("inspect-body").textContent="";$("inspect-raw").textContent="";
  $("inspect-content").hidden=true;$("inspect-placeholder").hidden=false;
}
function renderInspection() {
  const rows=document.createDocumentFragment();
  inspectMessages.forEach(message=>{
    const row=element("button","message-row");row.type="button";
    row.classList.toggle("selected",String(message.id)===inspectSelected);
    const copy=element("span","message-row-copy");
    copy.append(element("span","message-row-title",message.subject || t("(No subject)")),element("span","message-row-subtitle",t(mailFolderLabels[message.folder] || message.folder)+" · "+(message.from || "")),element("span","message-row-subtitle",message.to || ""));
    row.append(copy);row.addEventListener("click",()=>inspectMessage(message));rows.append(row);
  });
  $("inspect-messages").replaceChildren(rows);$("inspect-empty").hidden=inspectMessages.length>0;
}
async function loadInspection() {
  const version=++inspectVersion;inspectReadVersion++;
  inspectSelected=null;inspectMessages=[];renderInspection();
  $("inspect-content").hidden=true;$("inspect-placeholder").hidden=false;
  formError("inspect-error");$("inspect-messages").setAttribute("aria-busy","true");
  try {
    const selectedFolder=$("inspect-folder").value;
    const folders=selectedFolder === "all" ? Object.keys(mailFolderLabels) : [selectedFolder];
    const results=await Promise.all(folders.map(folder=>api(`/api/admin/messages?username=${encodeURIComponent(inspectUsername)}&folder=${encodeURIComponent(folder)}`)));
    const data={messages:results.flatMap(result=>result.messages || []).sort((a,b)=>String(b.internal_date).localeCompare(String(a.internal_date)))};
    if(version!==inspectVersion) return;
    inspectMessages=data.messages || [];renderInspection();
  } catch(error) {if(version===inspectVersion) formError("inspect-error",error.message);}
  finally {if(version===inspectVersion) $("inspect-messages").removeAttribute("aria-busy");}
}
function openInspection(username) {clearInspection();inspectUsername=username;$("inspect-user").textContent=username;$("inspect-folder").value="all";$("inspect-dialog").showModal();loadInspection();}
async function inspectMessage(message) {
  const version=++inspectReadVersion;formError("inspect-error");
  try {
    const data=await api(`/api/admin/messages/${encodeURIComponent(message.id)}?username=${encodeURIComponent(inspectUsername)}`);
    if(version!==inspectReadVersion) return;
    inspectSelected=String(message.id);const preview=data.message || {};
    $("inspect-subject").textContent=preview.subject || t("(No subject)");
    $("inspect-from").textContent=preview.from || "—";$("inspect-to").textContent=preview.to || "—";$("inspect-date").textContent=preview.date || "—";
    $("inspect-body").textContent=preview.text || t("(Empty message)");$("inspect-raw").textContent=data.raw || "";
    $("inspect-message-folder").textContent=t(mailFolderLabels[message.folder] || message.folder);
    $("inspect-content").hidden=false;$("inspect-placeholder").hidden=true;renderInspection();
  } catch(error) {if(version===inspectReadVersion) formError("inspect-error",error.message);}
}
$("inspect-folder").addEventListener("change",loadInspection);
$("inspect-dialog").addEventListener("close",clearInspection);
async function openQuota(username) {
  quotaUsername=username;quotaControl=null;$("quota-user").textContent=username;formError("quota-error");
  $("quota-usage").textContent=t("Loading quota…");$("quota-byte-control").replaceChildren();$("quota-dialog").showModal();
  try {
    const data=await api(`/api/admin/quota?username=${encodeURIComponent(username)}`);if(quotaUsername!==username) return;
    const usage=data.usage || data;
    $("quota-usage").textContent=t("{used} used · {messages} messages",{used:bytes(usage.bytes),messages:usage.messages});
    $("quota-inherit-bytes").checked=usage.quota_bytes===null || usage.quota_bytes===undefined;
    const input=element("input");input.id="quota-bytes";input.type="text";input.inputMode="decimal";
    const unit=element("select");unit.setAttribute("aria-label",t("Size unit"));
    $("quota-byte-control").className="byte-control";$("quota-byte-control").append(input,unit);
    const binding=PostPlusSize.create(input,unit,usage.quota_bytes ?? usage.max_bytes,{min:1,max:2**50});
    quotaControl={read:binding.read,disable:flag=>{input.disabled=flag;unit.disabled=flag;}};quotaControl.disable($("quota-inherit-bytes").checked);
  } catch(error) {formError("quota-error",error.message);}
}
$("quota-inherit-bytes").addEventListener("change",()=>quotaControl?.disable($("quota-inherit-bytes").checked));
$("quota-dialog").addEventListener("close",()=>{quotaUsername="";quotaControl=null;});
$("quota-form").addEventListener("submit",event=>{
  event.preventDefault();if(!quotaControl) return;
  busy(event.currentTarget,async()=>{
    formError("quota-error");
    try {let quota_bytes=null; if(!$("quota-inherit-bytes").checked) {try {quota_bytes=quotaControl.read();}catch(problem){throw new Error(PostPlusI18n.error({error:problem.message}));}}await api("/api/admin/quota",{method:"POST",body:{username:quotaUsername,quota_bytes}});$("quota-dialog").close();showNotice(t("Mailbox quota updated."));}
    catch(error) {formError("quota-error",error.message);}
  });
});

document.title = t("PostPlus · Administration");
(async () => {try {await signedIn(await api("/api/session",{quiet:true}));} catch {$("login-email").focus();}})();
