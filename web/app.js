"use strict";

const t = (...args) => PostPlusI18n.t(...args);
const $ = (id) => document.getElementById(id);
const state = { user: null, messages: [], selected: null, previews: new Map(), view: "INBOX", loading: false, readVersion: 0, listVersion: 0, folders: [], usage: null, draftId: null, composeDirty: false, composeSaving: false };
const folderLabels = {INBOX:"Inbox",Sent:"Sent",Drafts:"Drafts",Trash:"Trash",Junk:"Junk",Archive:"Archive"};
const folderIcons = {INBOX:"inbox",Sent:"send",Drafts:"file-pencil",Trash:"trash",Junk:"shield-exclamation",Archive:"archive"};
const messageReader=PostPlusMailReader.create($("message-body"));
const verificationCodes=PostPlusVerificationCode.create($("verification-code"),{request:api});
let noticeTimer;
let mailboxKeys=null;
let verificationRefresh=null;
function refreshVerificationCode(){
  if(state.user && ["INBOX","Trash"].includes(state.view))return verificationCodes.load(state.view);
  verificationCodes.reset();
}
function scheduleVerificationRefresh(){
  clearTimeout(verificationRefresh);verificationRefresh=null;
  if(!state.user)return;
  verificationRefresh=setTimeout(async()=>{
    verificationRefresh=null;
    if(!state.user)return;
    if(!document.hidden)await refreshVerificationCode();
    scheduleVerificationRefresh();
  },15000);
}
document.addEventListener("visibilitychange",()=>{if(state.user&&!document.hidden)refreshVerificationCode();});
const loginAddress=PostPlusAddress.create($("login-email"),$("login-domain"));
const mailDomainReady=api("/api/public/config",{quiet:true}).then(data=>{loginAddress.setDomain(data.domain);return true;}).catch(()=>false);

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
  if ((method !== "GET" || path.startsWith("/api/api-keys")) && state.user) headers["X-CSRF-Token"] = state.user.csrf;
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

function bytes(value) { return PostPlusSize.format(value); }

function element(tag, className, text) {
  const result = document.createElement(tag);
  if (className) result.className = className;
  if (text !== undefined) result.textContent = text;
  return result;
}
function icon(name) {
  const namespace="http://www.w3.org/2000/svg",svg=document.createElementNS(namespace,"svg"),use=document.createElementNS(namespace,"use");
  svg.setAttribute("class","ui-icon");svg.setAttribute("aria-hidden","true");svg.setAttribute("focusable","false");use.setAttribute("href",`/icons.svg#${name}`);svg.append(use);return svg;
}
function closeMoveMenu(restoreFocus=false){
  $("message-move-menu").hidden=true;$("message-move").setAttribute("aria-expanded","false");
  if(restoreFocus)$("message-move").focus();
}

function signedOut() {
  PostPlusPreferences.closeNavigation();
  verificationCodes.reset();
  closeMoveMenu();
  clearTimeout(verificationRefresh);verificationRefresh=null;
  mailboxKeys?.dispose();mailboxKeys=null;
  state.user = null;
  state.messages = [];
  state.previews.clear();
  state.selected = null;
  state.readVersion++;
  state.listVersion++;
  state.draftId = null;
  state.composeDirty = false;
  state.folders = [];
  state.usage = null;
  document.querySelectorAll("dialog[open]").forEach((dialog) => dialog.close());
  $("login-screen").hidden = false;
  $("app-screen").hidden = true;
  $("login-password").value = "";
  $("compose-form").reset();
  $("message-list").replaceChildren();
  messageReader.clear();
  $("message-raw").textContent = "";
  $("login-email").focus();
  document.title = t("PostPlus · Your mail, in order");
}

async function signedIn(user) {
  state.user = user;
  scheduleVerificationRefresh();
  $("login-screen").hidden = true;
  $("app-screen").hidden = false;
  $("user-address").textContent = user.username;
  $("user-name").textContent = user.username.split("@")[0];
  $("user-avatar").textContent = user.username.slice(0, 1);
  $("login-password").value = "";
  await switchView("INBOX");
}

$("mailbox-keys-open").addEventListener("click",()=>{
  if(!state.user)return;
  mailboxKeys?.dispose();
  mailboxKeys=PostPlusKeyPermissions.mount($("mailbox-keys-content"),{api,onError:message=>showNotice(message,true)});
  $("mailbox-keys-dialog").showModal();
});
$("mailbox-keys-dialog").addEventListener("close",()=>{mailboxKeys?.dispose();mailboxKeys=null;});

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
  try { await api("/api/logout", { method: "POST" }); signedOut(); }
  catch (error) { showNotice(error.message, true); }
});

function folderBadgeCount(name, folder) {
  const value = name === "Drafts" ? folder?.total : ["INBOX","Junk","Archive"].includes(name) ? folder?.unread : 0;
  return Number.isSafeInteger(value) && value > 0 ? value : 0;
}

function renderFolderState() {
  $("folder-title").textContent = t(folderLabels[state.view]);
  for (const [name,label] of Object.entries(folderLabels)) {
    const nav = $(`nav-${name.toLowerCase()}`);
    nav.classList.toggle("active",name === state.view);
    if (name === state.view) nav.setAttribute("aria-current","page"); else nav.removeAttribute("aria-current");
    const count = state.folders.find(folder => folder.name === name);
    const badge = $(`count-${name.toLowerCase()}`);
    badge.textContent = String(folderBadgeCount(name,count));
    badge.hidden = !Number(badge.textContent);
  }
  $("message-delete").replaceChildren(icon("trash"),element("span","",t(state.view === "Trash" ? "Delete permanently" : "Move to Trash")));
  $("draft-edit").hidden = state.view !== "Drafts";
  $("message-archive").hidden = state.view === "Archive" || state.view === "Drafts";
  closeMoveMenu();
  const menu=$("message-move-menu");menu.replaceChildren();
  for (const [name,label] of Object.entries(folderLabels)) if(name !== state.view) {
    const option=element("button");option.type="button";option.setAttribute("role","menuitem");option.tabIndex=-1;option.dataset.moveFolder=name;
    option.append(icon(folderIcons[name]),element("span","",t(label)));option.addEventListener("click",()=>{closeMoveMenu(true);return moveMessage(name);});menu.append(option);
  }
  if (state.user) document.title = `${t(folderLabels[state.view])} · ${state.user.username} · PostPlus`;
  $("mailbox-usage").hidden = !state.usage;
  if (state.usage) {
    $("usage-progress").value = Math.min(100,100 * state.usage.bytes / state.usage.max_bytes);
    $("usage-text").textContent = t("{used} of {limit}",{used:bytes(state.usage.bytes),limit:bytes(state.usage.max_bytes)});
  }
}
async function switchView(view) {
  if (!Object.hasOwn(folderLabels,view)) return;
  state.view = view;
  verificationCodes.reset();
  clearReader();
  state.messages = [];
  renderMessages();
  renderFolderState();
  await loadInbox();
}
document.querySelectorAll("[data-folder]").forEach(button => button.addEventListener("click",()=>switchView(button.dataset.folder)));
$("refresh").addEventListener("click", loadInbox);

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
    const avatar = element("span", "avatar", (state.view === "Sent" || state.view === "Drafts" ? preview?.to : preview?.from)?.slice(0, 1) || "✉");
    avatar.setAttribute("aria-hidden", "true");
    const copy = element("span", "message-row-copy");
    copy.append(element("span", "message-row-title", title));
    copy.append(element("span", "message-row-subtitle", (state.view === "Sent" || state.view === "Drafts" ? preview?.to : preview?.from) || `${bytes(message.size)} · ${t(message.seen ? "Read" : "Unread")}`));
    const dot = element("span", "message-dot");
    dot.setAttribute("aria-hidden", "true");
    button.append(avatar, copy, dot);
    button.addEventListener("click", () => openMessage(id));
    fragment.append(button);
  });
  $("message-list").replaceChildren(fragment);
  $("message-total").textContent = t(state.messages.length === 1 ? "{count} message" : "{count} messages", {count: state.messages.length});
  $("empty-mail").hidden = state.messages.length !== 0;
}

function clearReader() {
  state.selected = null;
  state.readVersion++;
  closeMoveMenu();
  messageReader.clear();
  $("message-raw").textContent="";
  $("reader-content").hidden = true;
  $("reader-placeholder").hidden = false;
  document.querySelector(".mail-workspace").classList.remove("reading");
}

async function loadInbox() {
  if (!state.user) return;
  void refreshVerificationCode();
  const version = ++state.listVersion;
  const folder = state.view;
  state.loading = true;
  $("refresh").disabled = true;
  $("message-list").setAttribute("aria-busy", "true");
  $("mail-status").textContent = t("Syncing…");
  const user = state.user;
  try {
    const [data, folders] = await Promise.all([api(`/api/messages?folder=${encodeURIComponent(folder)}`),api("/api/folders")]);
    if (state.user !== user || version !== state.listVersion) return;
    state.folders = folders.folders || [];
    state.usage = folders.usage || null;
    renderFolderState();
    state.messages = data.messages;
    if (!state.selected || !state.messages.some((message) => String(message.id) === state.selected)) clearReader();
    renderMessages();
    $("mail-status").textContent = t("Updated at {time}", {time: new Date().toLocaleTimeString(PostPlusI18n.language, { hour: "2-digit", minute: "2-digit" })});
    document.title = `${t(folderLabels[state.view])} · ${user.username} · PostPlus`;
  } catch (error) {
    if (version !== state.listVersion) return;
    $("mail-status").textContent = t("Sync failed");
    showNotice(error.message, true);
  } finally {
    if (version !== state.listVersion) return;
    state.loading = false;
    $("refresh").disabled = false;
    $("message-list").removeAttribute("aria-busy");
  }
}

async function openMessage(id) {
  clearReader();const version = state.readVersion;
  $("reader").setAttribute("aria-busy", "true");
  try {
    const data = await api(`/api/messages/${encodeURIComponent(id)}`);
    if (version !== state.readVersion || !state.user) return;
    state.selected = id;
    const preview = data.message || {};
    // List/draft metadata must not retain rendered HTML and inline image data.
    state.previews.set(id,{subject:preview.subject,from:preview.from,to:preview.to,date:preview.date,text:preview.text});
    const message = state.messages.find((item) => String(item.id) === id);
    if (message && !message.seen) {
      message.seen=true;const folder=state.folders.find(item=>item.name===state.view);
      if(folder){folder.unread=Math.max(0,(folder.unread ?? folder.unseen ?? 0)-1);folder.unseen=folder.unread;}
    }
    $("message-subject").textContent = preview.subject || t("(No subject)");
    $("message-from").textContent = preview.from || "—";
    $("message-to").textContent = preview.to || state.user.username;
    $("message-date").textContent = preview.date || "—";
    const imageBase=`/api/messages/${encodeURIComponent(id)}?image=`;
    messageReader.show(preview,{loadImage:index=>api(imageBase+index,{quiet:true})});
    $("message-raw").textContent = PostPlusMailReader.bodySource(data.raw);
    document.querySelector(".raw-message").open = false;
    $("reader-placeholder").hidden = true;
    $("reader-content").hidden = false;
    document.querySelector(".mail-workspace").classList.add("reading");
    $("reader").scrollTop = 0;
    renderMessages();
    renderFolderState();
    $("message-subject").focus({ preventScroll: true });
  } catch (error) { showNotice(error.message, true); }
  finally { if (version === state.readVersion) $("reader").removeAttribute("aria-busy"); }
}

$("reader-back").addEventListener("click", () => {
  document.querySelector(".mail-workspace").classList.remove("reading");
  document.querySelector('.message-row[aria-pressed="true"]')?.focus();
});

function composePayload() {
  return {to:$("compose-to").value.split(/[,;，；\n]/).map(value=>value.trim()).filter(Boolean),subject:$("compose-subject").value,text:$("compose-text").value};
}
function resetCompose() {$("compose-form").reset();state.draftId=null;state.composeDirty=false;$("draft-status").textContent="";}
function beginCompose(draft = null) {
  if(state.composeSaving)return;
  if (state.composeDirty) {$("compose-dialog").showModal();showNotice(t("Save or discard your current changes before opening another draft."));return;}
  resetCompose();
  if (draft) {state.draftId=state.selected;$("compose-to").value=draft.to || "";$("compose-subject").value=draft.subject || "";$("compose-text").value=draft.text || "";}
  $("compose-title").textContent=t(draft ? "Edit draft" : "Compose a message");
  formError("compose-error");
  $("compose-dialog").showModal();
}
$("compose-open").addEventListener("click",()=>beginCompose());
$("draft-edit").addEventListener("click",()=>beginCompose(state.previews.get(state.selected)));
$("compose-form").addEventListener("input",()=>{state.composeDirty=true;$("draft-status").textContent=t("Unsaved changes");});
$("compose-dialog").addEventListener("cancel",event=>{if(state.composeSaving)event.preventDefault();});
$("compose-discard").addEventListener("click",()=>{resetCompose();$("compose-dialog").close();});
function setComposeBusy(flag) {state.composeSaving=flag;$("compose-form").querySelectorAll("input,textarea,button").forEach(control=>{control.disabled=flag;});}
$("draft-save").addEventListener("click",async()=>{
  if(state.composeSaving)return;
  setComposeBusy(true);
  formError("compose-error");
  const user=state.user;
  try {
    const payload=composePayload(); if(state.draftId) payload.id=state.draftId;
    const result=await api("/api/drafts",{method:"POST",body:payload});
    if(state.user!==user)return;
    state.draftId=String(result.id);
    state.previews.delete(state.draftId);
    state.composeDirty=false;
    $("draft-status").textContent=t("Draft saved");
    showNotice(t("Draft saved"));
    await loadInbox();
  } catch(error) {formError("compose-error",error.message);}
  finally {setComposeBusy(false);}
});
$("compose-form").addEventListener("submit",event=>{
  event.preventDefault();
  if(state.composeSaving)return;
  busy(event.currentTarget,async()=>{
    formError("compose-error");
    const payload=composePayload();
    if(!payload.to.length) {formError("compose-error",t("Enter at least one recipient email address."));return;}
    if(state.draftId) payload.draft_id=state.draftId;
    setComposeBusy(true);
    const user=state.user;
    try {
      await api("/api/send",{method:"POST",body:payload});
      if(state.user!==user)return;
      $("compose-dialog").close();resetCompose();
      showNotice(t("Your message has been queued for delivery."));
      await loadInbox();
    } catch(error) {formError("compose-error",error.message);}
    finally {setComposeBusy(false);}
  });
});
async function moveMessage(folder) {
  if (!state.selected || !Object.hasOwn(folderLabels,folder)) return;
  try {await api(`/api/messages/${encodeURIComponent(state.selected)}/move`,{method:"POST",body:{folder}});clearReader();showNotice(t("Message moved to {folder}.",{folder:t(folderLabels[folder])}));await loadInbox();}
  catch(error) {showNotice(error.message,true);}
}
function openMoveMenu(last=false){
  if(!state.selected)return;
  $("message-move-menu").hidden=false;$("message-move").setAttribute("aria-expanded","true");
  const items=Array.from($("message-move-menu").querySelectorAll("button"));(last?items.at(-1):items[0])?.focus();
}
$("message-move").addEventListener("click",()=>{$("message-move-menu").hidden?openMoveMenu():closeMoveMenu();});
$("message-move").addEventListener("keydown",event=>{if(event.key==="ArrowDown"||event.key==="ArrowUp"){event.preventDefault();openMoveMenu(event.key==="ArrowUp");}});
$("message-move-menu").addEventListener("keydown",event=>{
  if(event.key==="Escape"){event.preventDefault();closeMoveMenu(true);return;}
  if(event.key==="Tab"){closeMoveMenu(true);return;}
  const items=Array.from($("message-move-menu").querySelectorAll("button")),index=items.indexOf(document.activeElement);
  let next;if(event.key==="ArrowDown")next=(index+1)%items.length;else if(event.key==="ArrowUp")next=(index-1+items.length)%items.length;else if(event.key==="Home")next=0;else if(event.key==="End")next=items.length-1;
  if(next!==undefined){event.preventDefault();items[next]?.focus();}
});
document.addEventListener("click",event=>{if(!$("message-move-control").contains(event.target))closeMoveMenu();});
$("message-archive").addEventListener("click",()=>moveMessage("Archive"));
$("message-delete").addEventListener("click",()=>{
  if(!state.selected) return;
  if(state.view !== "Trash") {moveMessage("Trash");return;}
  formError("delete-error");$("delete-dialog").showModal();
});
$("delete-form").addEventListener("submit",event=>{
  event.preventDefault();
  busy(event.currentTarget,async()=>{
    if(!state.selected) return;
    formError("delete-error");
    try {await api(`/api/messages/${encodeURIComponent(state.selected)}?permanent=true`,{method:"DELETE"});state.previews.delete(state.selected);clearReader();$("delete-dialog").close();showNotice(t("Message deleted."));await loadInbox();}
    catch(error) {formError("delete-error",error.message);}
  });
});

document.querySelectorAll("[data-close]").forEach((button) => {
  button.addEventListener("click", () => $(button.dataset.close).close());
});

(async () => {
  try { await signedIn(await api("/api/session", { quiet: true })); }
  catch { $("login-email").focus(); }
})();


document.addEventListener("postplus:language", () => {
  if($("mailbox-keys-dialog").open && state.user){mailboxKeys?.dispose();mailboxKeys=PostPlusKeyPermissions.mount($("mailbox-keys-content"),{api,onError:message=>showNotice(message,true)});}
  verificationCodes.translate();
  document.title = state.user ? `${t(folderLabels[state.view])} · ${state.user.username} · PostPlus` : t("PostPlus · Your mail, in order");
  $("notice").hidden = true;
  for (const id of ["login-error", "compose-error", "delete-error"]) formError(id);
  $("mail-status").textContent = t(state.loading ? "Syncing…" : "Ready");
  renderMessages();
  renderFolderState();
  $("compose-title").textContent=t(state.draftId ? "Edit draft" : "Compose a message");
  $("draft-status").textContent=state.composeDirty ? t("Unsaved changes") : state.draftId ? t("Draft saved") : "";
  if (state.selected) {
    const preview = state.previews.get(state.selected) || {};
    $("message-subject").textContent = preview.subject || t("(No subject)");
  }
});
document.title = t("PostPlus · Your mail, in order");
$("mail-status").textContent = t("Ready");
$("message-total").textContent = t("{count} messages", {count:0});
