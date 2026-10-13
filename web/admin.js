"use strict";
const t = (...args) => PostPlusI18n.t(...args);
const $ = id => document.getElementById(id);
const state = {user:null,view:"overview",userMode:"create"};
const viewLabels = {overview:"Overview",accounts:"User accounts",queue:"Delivery queue",logs:"Service logs","api-keys":"API keys",settings:"Server settings"};
const inspectionReader=PostPlusMailReader.create($("inspect-body"));
let settingsData = null;
let settingsEditor = null;
let settingsLoading = false;
let settingsSaving = false;
let backupVersion=0,backupTimer=null,shutdownPending=false;
let acmeControl=null;
let passwordPolicyData=null, passwordPolicyVersion=0, userDialogVersion=0, policySaving=false;
let apiKeysData=null,apiKeysVersion=0,apiKeyDialogVersion=0,apiKeyCreating=false,apiKeyRevoking=false,apiKeyRevokeTarget=null;
let restartJob=null,restartVersion=0,restartTimer=null,restartStarted=0,restartBusy=false,restartText="",restartSubmitting=false;
let noticeTimer;
const accountAddress=PostPlusAddress.create($("new-email"),$("new-email-domain"));
const loginAddress=PostPlusAddress.create($("login-email"),$("login-domain"));
const mailDomainReady=api("/api/public/config",{quiet:true}).then(data=>{accountAddress.setDomain(data.domain);loginAddress.setDomain(data.domain);return true;}).catch(()=>false);

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

async function api(path, { method = "GET", body, quiet = false, timeoutMs = 0 } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if ((method !== "GET" || path.startsWith("/api/admin/api-keys")) && state.user) headers["X-CSRF-Token"] = state.user.csrf;
  const controller=timeoutMs ? new AbortController() : null;
  const timeout=controller ? setTimeout(()=>controller.abort(),timeoutMs) : null;
  try {
  let response;
  try {
    response = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin", cache: "no-store", ...(controller ? {signal:controller.signal} : {}) });
  } catch {
    throw new Error(t("Cannot connect to the server. Check your connection and try again."));
  }
  let data;
  try { data = await response.json(); }
  catch { throw new Error(t("The server returned an unreadable response.")); }
  if (!response.ok || !data.ok) {
    if (response.status === 401 && path !== "/api/login" && !quiet) {
      if(restartBusy && restartIncludesAdmin())restartReconnect();
      else {signedOut();showNotice(t("Your session has expired. Please sign in again."), true);}
    }
    const error = new Error(data.code==="password_policy_violation" ? passwordViolationMessage(data.violations,data.policy,data.max_password_bytes) : PostPlusI18n.error(data));
    error.field = data.field;
    error.status = response.status;
    error.data = data;
    throw error;
  }
  return data;
  } finally {if(timeout!==null)clearTimeout(timeout);}
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
  clearRestart();
  backupVersion++;clearTimeout(backupTimer);backupTimer=null;shutdownPending=false;
  $("backup-create").disabled=false;$("backup-download").hidden=true;
  maintenanceStatus("backup-status","");maintenanceStatus("shutdown-status","");
  formError("backup-error");formError("shutdown-error");$("settings-edit").disabled=false;
  $("shutdown-open").disabled=false;
  passwordPolicyData=null;passwordPolicyVersion++;userDialogVersion++;
  apiKeysData=null;apiKeysVersion++;clearApiKeySecret();apiKeyRevokeTarget=null;
  $("api-keys-body").replaceChildren();$("api-keys-status").textContent="";formError("api-keys-error");
  $("api-keys-table").removeAttribute("aria-busy");$("api-keys-empty").hidden=true;$("api-key-create-open").disabled=true;
  PostPlusPreferences.closeNavigation();
  document.querySelectorAll("dialog[open]").forEach(dialog => dialog.close());
  $("login-screen").hidden = false;
  $("app-screen").hidden = true;
  $("login-password").value = "";
  $("user-form").reset();
  for (const id of ["users-body", "queue-body", "logs-body", "settings-fields"]) $(id).replaceChildren();
  logData = null;
  logVersion++;
  settingsData = null;
  settingsEditor?.dispose();
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
  await loadPasswordPolicy();
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
      await mailDomainReady;
      const user = await api("/api/login", { method: "POST", body: { username: loginAddress.address(), password: $("login-password").value } });
      await signedIn(user);
    } catch (error) { formError("login-error", error.message); }
  });
});

$("logout").addEventListener("click", async () => {
  clearApiKeySecret();
  if($("api-key-dialog").open)$("api-key-dialog").close();
  try { await api("/api/logout", { method: "POST" }); signedOut(); }
  catch (error) { showNotice(error.message, true); }
});


async function switchView(view) {
  if(restartBusy)return;
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
  else if (view === "api-keys") await loadApiKeys();
  else if (view === "settings") { if (!settingsData) await loadSettings(); }
  else await loadAdmin();
}
document.querySelectorAll("[data-view]").forEach(button => button.addEventListener("click", () => switchView(button.dataset.view)));
$("admin-refresh").addEventListener("click", () => state.view === "logs" ? loadLogs() : state.view === "api-keys" ? loadApiKeys() : loadAdmin());
async function loadAdmin() {
  if (!state.user?.admin || restartBusy) return;
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

function apiKeyDate(value,empty="—") {
  if(value===null || value===undefined)return empty;
  const date=new Date(Number(value)*1000);
  return Number.isFinite(date.getTime()) ? date.toLocaleString(PostPlusI18n.language) : "—";
}
function apiKeyStatus(key) {
  if(key.revoked_at!==null && key.revoked_at!==undefined)return "Revoked";
  if(key.expires_at!==null && key.expires_at!==undefined && Number(key.expires_at)*1000<=Date.now())return "Expired";
  return key.active ? "Active" : "Inactive";
}
function renderApiKeys() {
  if(!apiKeysData)return;
  const rows=document.createDocumentFragment();
  for(const key of apiKeysData.api_keys) {
    const row=element("tr"),identity=element("td","api-key-identity"),status=apiKeyStatus(key);
    identity.append(element("strong","",key.name),element("span","api-key-owner",key.owner || ""));
    const prefix=element("td","api-key-prefix",`${key.prefix}…`);
    const badge=element("td");badge.append(element("span",`role-badge api-key-status ${status.toLowerCase()}`,t(status)));
    const action=element("td"),button=element("button","table-action",t("Revoke"));button.type="button";
    button.disabled=key.revoked_at!==null && key.revoked_at!==undefined;
    button.setAttribute("aria-label",t("Revoke API key {name}",{name:key.name}));
    button.addEventListener("click",()=>openApiKeyRevoke(key));action.append(button);
    row.append(identity,prefix,badge,element("td","",apiKeyDate(key.created_at)),element("td","",apiKeyDate(key.expires_at,t("Never expires"))),element("td","",apiKeyDate(key.last_used_at,t("Never used"))),action);
    rows.append(row);
  }
  $("api-keys-body").replaceChildren(rows);$("api-keys-empty").hidden=apiKeysData.api_keys.length!==0;
  const active=apiKeysData.api_keys.filter(key=>key.active).length,limit=apiKeysData.max_active_keys || 100;
  $("api-keys-status").textContent=t("{count} active keys · maximum {limit}",{count:active,limit});
  $("api-key-create-open").disabled=active>=limit;
}
async function loadApiKeys() {
  if(!state.user?.admin)return;
  const user=state.user,version=++apiKeysVersion;
  $("api-keys-status").textContent=t("Loading API keys…");formError("api-keys-error");
  $("api-keys-table").setAttribute("aria-busy","true");$("api-key-create-open").disabled=true;
  try {
    const data=await api("/api/admin/api-keys");
    if(version!==apiKeysVersion || user!==state.user)return;
    if(!Array.isArray(data.api_keys))throw new Error(t("The server returned an unreadable response."));
    apiKeysData=data;renderApiKeys();
  } catch(error) {
    if(version===apiKeysVersion && user===state.user){$("api-keys-status").textContent="";formError("api-keys-error",error.message);}
  } finally {if(version===apiKeysVersion)$("api-keys-table").removeAttribute("aria-busy");}
}
function clearApiKeySecret() {
  apiKeyDialogVersion++;$("api-key-secret").value="";$("api-key-created").hidden=true;
  $("api-key-copy-status").textContent="";
}
function openApiKeyCreate() {
  if(!state.user?.admin || apiKeyCreating)return;
  clearApiKeySecret();$("api-key-form").reset();formError("api-key-error");
  $("api-key-name").removeAttribute("aria-invalid");$("api-key-expiry").removeAttribute("aria-invalid");
  $("api-key-create-fields").hidden=false;$("api-key-create-submit").hidden=false;$("api-key-create-submit").disabled=false;
  $("api-key-create-cancel").hidden=false;$("api-key-created-done").hidden=true;
  $("api-key-dialog").showModal();$("api-key-name").focus();
}
$("api-key-create-open").addEventListener("click",openApiKeyCreate);
$("api-key-dialog").addEventListener("close",clearApiKeySecret);
$("api-key-secret").addEventListener("click",()=>$("api-key-secret").select());
$("api-key-copy").addEventListener("click",async()=>{
  const secret=$("api-key-secret").value,version=apiKeyDialogVersion;
  if(!secret)return;
  $("api-key-secret").focus();$("api-key-secret").select();
  try {
    if(!navigator.clipboard?.writeText)throw new Error();
    await navigator.clipboard.writeText(secret);
    if(version===apiKeyDialogVersion)$("api-key-copy-status").textContent=t("API key copied.");
  } catch {if(version===apiKeyDialogVersion)$("api-key-copy-status").textContent=t("Copy is unavailable. The key is selected; copy it manually.");}
});
$("api-key-form").addEventListener("submit",async event=>{
  event.preventDefault();if(apiKeyCreating || !state.user?.admin || !$("api-key-created").hidden)return;
  formError("api-key-error");const name=$("api-key-name").value.trim(),expiry=$("api-key-expiry").value;
  $("api-key-name").removeAttribute("aria-invalid");$("api-key-expiry").removeAttribute("aria-invalid");
  const nameLimit=80,expiryLimit=3650;
  if(!name || new TextEncoder().encode(name).length>nameLimit){formError("api-key-error",t("Enter a key name using at most {count} UTF-8 bytes.",{count:nameLimit}));$("api-key-name").setAttribute("aria-invalid","true");$("api-key-name").focus();return;}
  const body={name};
  if(expiry!=="" || $("api-key-expiry").validity?.badInput){const days=Number(expiry);if($("api-key-expiry").validity?.badInput || !Number.isInteger(days) || days<1 || days>expiryLimit){formError("api-key-error",t("Choose an expiry from 1 to {count} whole days, or leave it blank.",{count:expiryLimit}));$("api-key-expiry").setAttribute("aria-invalid","true");$("api-key-expiry").focus();return;}body.expires_in_days=days;}
  apiKeyCreating=true;const user=state.user,version=apiKeyDialogVersion;$("api-key-create-submit").disabled=true;$("api-key-form").setAttribute("aria-busy","true");
  try {
    const data=await api("/api/admin/api-keys",{method:"POST",body});
    if(user!==state.user){data.key="";return;}
    if(version!==apiKeyDialogVersion || !$("api-key-dialog").open){data.key="";showNotice(t("API key created. Its secret is no longer available. Revoke it and create another if needed."));await loadApiKeys();return;}
    if(typeof data.key!=="string" || !/^pp_[0-9a-f]{64}$/.test(data.key))throw new Error(t("The server returned an unreadable response."));
    $("api-key-secret").value=data.key;data.key="";$("api-key-create-fields").hidden=true;$("api-key-created").hidden=false;
    $("api-key-create-submit").hidden=true;$("api-key-create-cancel").hidden=true;$("api-key-created-done").hidden=false;
    $("api-key-secret").focus();$("api-key-secret").select();await loadApiKeys();
  } catch(error){if(user===state.user && version===apiKeyDialogVersion){formError("api-key-error",error.message);const field={name:"api-key-name",expires_in_days:"api-key-expiry"}[error.field];if(field){$(field).setAttribute("aria-invalid","true");$(field).focus();}}}
  finally{apiKeyCreating=false;$("api-key-create-submit").disabled=false;$("api-key-form").removeAttribute("aria-busy");}
});
function openApiKeyRevoke(key) {
  if(!state.user?.admin || apiKeyRevoking)return;
  apiKeyRevokeTarget={id:key.id,name:key.name};formError("api-key-revoke-error");
  $("api-key-revoke-name").textContent=key.name;$("api-key-revoke-dialog").showModal();
}
$("api-key-revoke-dialog").addEventListener("close",()=>{apiKeyRevokeTarget=null;$("api-key-revoke-name").textContent="";});
$("api-key-revoke-form").addEventListener("submit",async event=>{
  event.preventDefault();if(apiKeyRevoking || !apiKeyRevokeTarget || !state.user?.admin)return;
  const target=apiKeyRevokeTarget,user=state.user;apiKeyRevoking=true;formError("api-key-revoke-error");
  try {
    await busy(event.currentTarget,async()=>{
      await api(`/api/admin/api-keys/${encodeURIComponent(target.id)}`,{method:"DELETE"});
      if(user!==state.user)return;
      if(apiKeyRevokeTarget===target)$("api-key-revoke-dialog").close();
      showNotice(t("API key revoked."));await loadApiKeys();
    });
  } catch(error){if(user===state.user && apiKeyRevokeTarget===target)formError("api-key-revoke-error",error.message);}
  finally{apiKeyRevoking=false;}
});

async function openUserDialog(username = "") {
  const version=++userDialogVersion;
  state.userMode = username ? "password" : "create";
  $("user-form").reset();
  formError("user-error");
  $("user-dialog-title").textContent = username ? t("Reset password") : t("Create user");
  accountAddress.setAddress(username);
  $("admin-checkbox-label").hidden = Boolean(username);
  $("user-form").querySelector('[type="submit"]').disabled=true;
  $("account-password-hint").textContent=t("Loading password policy…");
  $("user-dialog").showModal();
  const [policy,domainReady]=await Promise.all([loadPasswordPolicy(),mailDomainReady]);
  if(version!==userDialogVersion || !$("user-dialog").open)return;
  $("user-form").querySelector('[type="submit"]').disabled=!policy || !domainReady;
  if(!domainReady)formError("user-error",t("Could not load the mail domain. Refresh this page and try again."));
  if(!policy)formError("user-error",t("Could not load the password policy. Close this window and try again."));
}

$("user-create-open").addEventListener("click", () => openUserDialog());
$("user-form").addEventListener("submit", (event) => {
  event.preventDefault();
  busy(event.currentTarget, async () => {
    formError("user-error");
    const password = $("new-password").value;
    const changing = state.userMode === "password";
    try {
      const username=accountAddress.address();
      const currentAccount = username === state.user?.username;
      if(!passwordPolicyData)throw new Error(t("Could not load the password policy. Close this window and try again."));
      const violations=checkPassword(password,passwordPolicyData);
      if(violations.length)throw new Error(passwordViolationMessage(violations,passwordPolicyData.policy,passwordPolicyData.max_password_bytes));
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
    } catch (error) {
      if(error.data?.code==="password_policy_violation" && error.data.policy){passwordPolicyData={...passwordPolicyData,policy:error.data.policy,max_password_bytes:error.data.max_password_bytes};renderPasswordHint();}
      formError("user-error", error.message);
    }
  });
});

document.querySelectorAll("[data-close]").forEach((button) => {
  button.addEventListener("click", () => $(button.dataset.close).close());
});
$("user-dialog").addEventListener("close", () => { userDialogVersion++;$("new-password").value = ""; });


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
    $("restart-open").disabled=data.restart_available===false;
    maintenanceStatus("settings-apply-hint",data.restart_available===false ? "This standalone service saves settings without restarting. Restart the affected services manually after saving." : "Saving validates the configuration and restarts only affected services. Other services continue running.");
    settingsEditor?.dispose();
    settingsEditor = PostPlusSettings.create($("settings-fields"),data.schema,data.values,{prefix:"config",secretStatus:data.secret_status,generateDkim:body=>api("/api/admin/dkim",{method:"POST",body})});
    $("settings-success").hidden = true;
    $("settings-form").hidden = false;
    setLink("open-webmail",data.web_url);
    $("server-links").hidden = false;
    if(data.restart && ["pending","running","complete","failed"].includes(data.restart.state) && data.restart.job_id)startRestart(data,{restored:true});
  } catch (error) { formError("settings-error",error.message); settingsEditor?.highlight(error.field); }
  finally { settingsLoading = false; $("settings-loading").hidden = true; }
}
$("settings-edit").addEventListener("click",loadSettings);
async function saveSettings({apply=true}={}) {
  if(settingsSaving || restartBusy || !settingsEditor)return false;
  if($("settings-form").hidden)return true;
  formError("settings-error");
  let values;
  try { values=settingsEditor.read(); }
  catch(error) {formError("settings-error",error.message);return false;}
  if(!Object.keys(values).length)return true;
  const user=state.user;
  settingsSaving=true;$("settings-save").disabled=true;$("settings-form").setAttribute("aria-busy","true");
  try {
    const body={revision:settingsData.revision,values};if(!apply)body.apply=false;
    const data=await api("/api/admin/config",{method:"POST",body});
    if(user!==state.user)return false;
    $("settings-pending").hidden=!data.restart_required;
    setLink("settings-open-admin",data.admin_url);setLink("settings-open-web",data.web_url);
    settingsEditor.clearSecrets();$("settings-form").hidden=true;$("settings-success").hidden=false;
    maintenanceStatus("settings-success-message",!apply ? "Settings saved without restarting services." : data.restart_error ? "Settings saved, but automatic restart could not be scheduled. Check service logs and restart the services." : data.restart_required ? "Settings saved. This standalone service cannot restart automatically. Restart PostPlus manually using the same configuration, then open the updated addresses." : "Settings saved. Affected services will restart automatically. Follow the progress below.");
    if(apply && data.restart)startRestart(data);
    return true;
  } catch(error) {formError("settings-error",error.message);settingsEditor?.highlight(error.field);return false;}
  finally {settingsSaving=false;$("settings-save").disabled=false;$("settings-form").removeAttribute("aria-busy");}
}
$("settings-form").addEventListener("submit",async event=>{
  event.preventDefault();
  if(await saveSettings()) {
    if($("settings-success").hidden)showNotice(t("No settings have changed."));
    else $("settings-success").scrollIntoView({block:"center"});
  }
});
function maintenanceStatus(id,key) {$(id).dataset.i18n=key;$(id).textContent=t(key);}
function restartIncludesAdmin() {return Boolean(restartJob?.services?.some(name=>/^(postplus-)?admin$/.test(name)));}
function restartControls(disabled) {
  restartBusy=disabled;$("settings-edit").disabled=disabled;$("restart-open").disabled=disabled || settingsData?.restart_available===false;
  $("shutdown-open").disabled=disabled;$("backup-create").disabled=disabled;
  document.querySelectorAll("[data-view]").forEach(button=>{button.disabled=disabled;});
}
function clearRestart() {
  restartVersion++;clearTimeout(restartTimer);restartTimer=null;restartJob=null;restartText="";restartControls(false);
  $("restart-panel").hidden=true;$("restart-status").textContent="";$("restart-services").textContent="";formError("restart-error");
}
function renderRestart() {
  if(!restartJob)return;
  $("restart-panel").hidden=false;$("restart-status").textContent=t(restartText);
  $("restart-services").textContent=t("Affected services: {services}",{services:(restartJob.services || []).join(", ") || t("None")});
}
function restartFailureText() {return restartJob?.rolled_back ? "Restart failed. The previous affected services were restored. Saved changes are still pending; correct them before retrying." : "Restart failed. Check service logs, correct the saved configuration, and try again.";}
function restartReconnect() {
  restartVersion++;clearTimeout(restartTimer);restartTimer=null;
  clearApiKeySecret();
  restartText="Administration is reconnecting. Open the updated administration address and sign in again to check that restarting completed.";
  renderRestart();
}
function startRestart(data,{restored=false}={}) {
  const job=data.restart || data;
  if(typeof job.job_id!=="string" || !Array.isArray(job.services))throw new Error(t("The server returned an unreadable response."));
  const version=++restartVersion;clearTimeout(restartTimer);restartJob={...job};restartStarted=Date.now();formError("restart-error");
  setLink("restart-open-admin",data.admin_url || settingsData?.admin_url || location.origin);
  setLink("restart-open-web",data.web_url || settingsData?.web_url || location.origin);
  setLink("restart-open-original",location.origin+"/");
  $("restart-open-original").hidden=new URL($("restart-open-admin").href).origin===location.origin && !job.rolled_back;
  if(restored && ["complete","failed"].includes(job.state)) {
    restartControls(false);restartText=job.state==="complete" ? "Service restart completed. Your current administration session is available." : restartFailureText();
    if(job.state==="failed")formError("restart-error",t(restartText));renderRestart();return;
  }
  restartControls(true);restartText="Restarting affected services… Existing connections to those services may close.";renderRestart();
  if(restartIncludesAdmin() && new URL($("restart-open-admin").href).origin!==location.origin){restartReconnect();return;}
  async function poll() {
    if(version!==restartVersion || !state.user)return;
    try {
      const status=await api(`/api/admin/restart?job_id=${encodeURIComponent(job.job_id)}`,{quiet:true,timeoutMs:5000});
      if(version!==restartVersion)return;
      restartJob={...restartJob,...(status.restart || status)};
      if(status.admin_url)setLink("restart-open-admin",status.admin_url);if(status.web_url)setLink("restart-open-web",status.web_url);
      if(restartJob.state==="complete") {
        restartControls(false);restartText=restartIncludesAdmin() ? "Services restarted. Open administration and sign in again; its previous session has ended." : "Affected services restarted. Your administration session remains available.";
        if(restartIncludesAdmin())$("settings-edit").disabled=true;
        renderRestart();return;
      }
      if(restartJob.state==="failed") {restartControls(false);restartText=restartFailureText();if(restartJob.rolled_back)$("restart-open-original").hidden=false;formError("restart-error",t(restartText));renderRestart();return;}
      if(!["pending","running"].includes(restartJob.state))throw new Error(t("The server returned an unreadable response."));
    } catch(error) {
      if(version!==restartVersion)return;
      if(error.status===401 || error.status===403){if(restartIncludesAdmin())restartReconnect();else {restartControls(false);restartText="Restart status needs a new sign-in. Open administration to check the result.";renderRestart();}return;}
    }
    if(Date.now()-restartStarted>=90000){restartText="Restart progress could not be confirmed. Open administration or check service logs before retrying.";restartControls(false);renderRestart();return;}
    renderRestart();restartTimer=setTimeout(poll,1500);
  }
  restartTimer=setTimeout(poll,750);
}
$("restart-open").addEventListener("click",()=>{if(restartBusy)return;formError("restart-dialog-error");$("restart-dialog").showModal();});
$("restart-form").addEventListener("submit",async event=>{
  event.preventDefault();if(restartSubmitting || restartBusy)return;restartSubmitting=true;const user=state.user;
  try {
    await busy(event.currentTarget,async()=>{
      formError("restart-dialog-error");
      const data=await api("/api/admin/restart",{method:"POST",body:{mode:"all"}});
      if(user!==state.user)return;startRestart(data);$("restart-dialog").close();
    });
  } catch(error){if(user===state.user)formError("restart-dialog-error",error.message);}
  finally{restartSubmitting=false;}
});
$("backup-create").addEventListener("click",async()=>{
  const version=++backupVersion;clearTimeout(backupTimer);formError("backup-error");
  $("backup-create").disabled=true;$("backup-download").hidden=true;
  maintenanceStatus("backup-status","Creating backup… This may take a few minutes.");
  try {
    const job=await api("/api/admin/backup",{method:"POST",body:{}});
    if(version!==backupVersion)return;
    async function poll() {
      if(version!==backupVersion)return;
      try {
        const data=await api(`/api/admin/backup?job_id=${encodeURIComponent(job.job_id)}`);
        if(version!==backupVersion)return;
        if(data.state==="running"){backupTimer=setTimeout(poll,1500);return;}
        if(data.state!=="complete")throw new Error(t("Backup failed. Check service logs and try again."));
        const url=new URL(data.download_url,location.origin);
        if(url.origin!==location.origin || url.pathname!=="/api/admin/backup/download")throw new Error(t("The server returned an unreadable response."));
        $("backup-download").href=url.href;$("backup-download").hidden=false;$("backup-create").disabled=false;
        maintenanceStatus("backup-status","Backup ready. Download it before the next backup or server restart.");
      } catch(error){if(version===backupVersion){maintenanceStatus("backup-status","");formError("backup-error",error.message);$("backup-create").disabled=false;}}
    }
    await poll();
  } catch(error){if(version===backupVersion){maintenanceStatus("backup-status","");formError("backup-error",error.message);$("backup-create").disabled=false;}}
});
$("shutdown-open").addEventListener("click",()=>{formError("shutdown-error");$("shutdown-dialog").showModal();});
$("shutdown-form").addEventListener("submit",event=>{
  event.preventDefault();if(shutdownPending)return;
  busy(event.currentTarget,async()=>{
    shutdownPending=true;formError("shutdown-error");
    try {
      if(!await saveSettings({apply:false}))throw new Error(t("Server settings could not be saved. Check the highlighted fields before shutting down."));
      await api("/api/admin/shutdown",{method:"POST",body:{}});
      backupVersion++;clearTimeout(backupTimer);
      maintenanceStatus("backup-status","");
      $("shutdown-dialog").close();$("shutdown-open").disabled=true;$("backup-create").disabled=true;$("backup-download").hidden=true;
      maintenanceStatus("shutdown-status","Shutdown requested. Check the terminal for completion. Start PostPlus manually to resume service.");
      $("settings-form").querySelectorAll("input,select,textarea,button").forEach(input=>{input.disabled=true;});
      $("settings-edit").disabled=true;
    } catch(error){shutdownPending=false;formError("shutdown-error",error.message);}
  });
});
document.addEventListener("postplus:language", () => {
  document.title = state.user ? `${t(viewLabels[state.view])} · PostPlus` : t("PostPlus · Administration");
  $("view-title").textContent = t(viewLabels[state.view]);
  $("notice").hidden = true;
  for (const id of ["login-error","user-error","logs-error","settings-error","api-keys-error","api-key-error","api-key-revoke-error"]) formError(id);
  $("user-dialog-title").textContent = t(state.userMode === "password" ? "Reset password" : "Create user");
  settingsEditor?.translate();
  renderPasswordHint();
  acmeControl?.translate();
  renderInspection();
  renderApiKeys();
  renderRestart();
  if (state.user) { loadAdmin(); renderLogs(); }
});

const mailFolderLabels={INBOX:"Inbox",Sent:"Sent",Drafts:"Drafts",Trash:"Trash",Junk:"Junk",Archive:"Archive"};
let inspectUsername="",inspectVersion=0,inspectReadVersion=0,inspectMessages=[],inspectSelected=null;
let quotaUsername="",quotaControl=null;
function clearInspection() {
  inspectUsername="";inspectVersion++;inspectReadVersion++;inspectMessages=[];inspectSelected=null;
  $("inspect-messages").replaceChildren();inspectionReader.clear();$("inspect-raw").textContent="";
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
  inspectionReader.clear();$("inspect-raw").textContent="";
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
  inspectionReader.clear();$("inspect-raw").textContent="";$("inspect-content").hidden=true;$("inspect-placeholder").hidden=false;
  try {
    const data=await api(`/api/admin/messages/${encodeURIComponent(message.id)}?username=${encodeURIComponent(inspectUsername)}`);
    if(version!==inspectReadVersion) return;
    inspectSelected=String(message.id);const preview=data.message || {};
    $("inspect-subject").textContent=preview.subject || t("(No subject)");
    $("inspect-from").textContent=preview.from || "—";$("inspect-to").textContent=preview.to || "—";$("inspect-date").textContent=preview.date || "—";
    inspectionReader.show(preview);$("inspect-raw").textContent=data.raw || "";
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

function passwordViolationMessage(violations=[],policy={},maximum=1024) {
  const labels={min_length:t("Use at least {count} characters.",{count:policy.min_length || 8}),max_password_bytes:t("The password must fit within {count} UTF-8 bytes.",{count:maximum}),require_uppercase:t("Include an uppercase letter (A–Z)."),require_lowercase:t("Include a lowercase letter (a–z)."),require_digit:t("Include a digit (0–9)."),require_symbol:t("Include a printable ASCII punctuation symbol."),invalid_utf8:t("Use valid Unicode characters.")};
  return violations.map(value=>labels[value] || t("The password does not meet the account policy.")).join(" ") || t("The password does not meet the account policy.");
}
function checkPassword(password,data) {
  const policy=data.policy,violations=[];
  if(Array.from(password).length<policy.min_length)violations.push("min_length");
  if(new TextEncoder().encode(password).length>data.max_password_bytes)violations.push("max_password_bytes");
  for(const [field,pattern] of [["require_uppercase",/[A-Z]/],["require_lowercase",/[a-z]/],["require_digit",/[0-9]/],["require_symbol",/[!-/:-@\[-`{-~]/]])if(policy[field] && !pattern.test(password))violations.push(field);
  return violations;
}
function renderPasswordHint() {
  if(!passwordPolicyData)return;
  const policy=passwordPolicyData.policy;
  $("new-password").minLength=policy.min_length;
  $("new-password").maxLength=passwordPolicyData.max_password_bytes;
  const requirements=["min_length",...Object.keys(policy).filter(key=>key.startsWith("require_") && policy[key])];
  $("account-password-hint").textContent=passwordViolationMessage(requirements,policy,passwordPolicyData.max_password_bytes);
}
function renderPasswordPolicy() {
  if(!passwordPolicyData)return;
  $("policy-min-length").value=passwordPolicyData.policy.min_length;
  for(const field of ["uppercase","lowercase","digit","symbol"])$("policy-"+field).checked=passwordPolicyData.policy["require_"+field];
  $("password-policy-save").disabled=false;renderPasswordHint();
}
async function loadPasswordPolicy() {
  if(!state.user?.admin)return null;
  const version=++passwordPolicyVersion,user=state.user;
  $("password-policy-status").textContent=t("Loading password policy…");
  $("password-policy-save").disabled=true;formError("password-policy-error");
  try {
    const data=await api("/api/admin/password-policy");
    if(version!==passwordPolicyVersion || user!==state.user)return null;
    passwordPolicyData=data;renderPasswordPolicy();$("password-policy-status").textContent="";return data;
  } catch(error){if(version===passwordPolicyVersion){$("password-policy-status").textContent="";formError("password-policy-error",error.message);}return null;}
}
$("password-policy-reload").addEventListener("click",loadPasswordPolicy);
$("password-policy-form").addEventListener("submit",async event=>{
  event.preventDefault();if(policySaving || !passwordPolicyData)return;
  formError("password-policy-error");const length=Number($("policy-min-length").value);
  if(!Number.isInteger(length) || length<8 || length>128){formError("password-policy-error",t("Choose a minimum length from 8 to 128."));$("policy-min-length").focus();return;}
  const policy={min_length:length};for(const field of ["uppercase","lowercase","digit","symbol"])policy["require_"+field]=$("policy-"+field).checked;
  policySaving=true;const user=state.user;
  $("password-policy-form").querySelectorAll("input,button").forEach(input=>{input.disabled=true;});
  try {
    const data=await api("/api/admin/password-policy",{method:"POST",body:{revision:passwordPolicyData.revision,policy}});
    if(user!==state.user)return;passwordPolicyData=data;renderPasswordPolicy();$("password-policy-status").textContent=t("Password policy saved. It applies immediately to new and reset passwords.");
  } catch(error){if(user===state.user)formError("password-policy-error",error.message);}
  finally{policySaving=false;$("password-policy-form").querySelectorAll("input,button").forEach(input=>{input.disabled=false;});}
});

document.title = t("PostPlus · Administration");
(async () => {try {await signedIn(await api("/api/session",{quiet:true}));} catch {$("login-email").focus();}})();
