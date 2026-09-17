"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const t = (...args) => PostPlusI18n.t(...args);
  let token = new URLSearchParams(location.hash.slice(1)).get("token") || "";
  history.replaceState(null, "", location.pathname + location.search);
  let errorData = null;
  let statusKey = "";
  let advancedEditor = null;
  let unlocking = false;
  let acmeControl = null;
  let saving = false;
  const portLabels = {smtp:"SMTP",pop3:"POP3",imap:"IMAP",web:"Webmail",admin:"Administration",auth:"Authentication",storage:"Mail storage",filter:"Mail filter",transfer:"Mail transfer",delivery_lock:"Delivery lock"};
  for (const [service, label] of Object.entries(portLabels)) {
    const group = document.createElement("div");
    const text = document.createElement("label");
    text.htmlFor = `setup-port-${service}`;
    text.dataset.i18n = label;
    text.textContent = t(label);
    const input = document.createElement("input");
    input.id = text.htmlFor;
    input.type = "number";
    input.min = "1";
    input.max = "65535";
    input.step = "1";
    input.required = true;
    group.append(text, input);
    $("setup-ports").append(group);
  }
  function render() {
    document.title = t("PostPlus · First-run setup");
    $("setup-status").textContent = statusKey ? t(statusKey) : "";
    $("setup-error").textContent = errorData ? (errorData.key ? t(errorData.key) : PostPlusI18n.error(errorData)) : "";
    $("setup-error").hidden = !errorData;
  }
  function fail(data) {
    errorData = data;
    render();
    $("setup-error").scrollIntoView({block:"center", behavior:"auto"});
    if (data?.field) advancedEditor?.highlight(data.field);
  }
  function modeChanged(userChange = false) {
    const secure = $("setup-mode").value === "tls";
    $("setup-tls").hidden = !secure;
    $("setup-certificate").required = secure;
    $("setup-key").required = secure;
    $("setup-bind").readOnly = !secure;
    if (!secure) $("setup-bind").value = "127.0.0.1";
    else if (userChange && $("setup-bind").value === "127.0.0.1") $("setup-bind").value = "0.0.0.0";
  }
  $("setup-mode").addEventListener("change", () => modeChanged(true));
  $("setup-brand").addEventListener("click", event => event.preventDefault());
  let adminEdited = false;
  $("setup-admin").addEventListener("input", () => { adminEdited = true; });
  $("setup-domain").addEventListener("input", () => {
    if (!adminEdited) $("setup-admin").value = `admin@${$("setup-domain").value.trim().toLowerCase()}`;
  });
  $("setup-form").addEventListener("input", event => event.target.removeAttribute("aria-invalid"));
  document.addEventListener("postplus:language", () => {render(); advancedEditor?.translate(); acmeControl?.translate();});
  async function request(method, body, path = "/api/setup") {
    let response;
    try {
      response = await fetch(path, {method, headers:{"X-Setup-Token":token, ...(body ? {"Content-Type":"application/json"} : {})}, body:body ? JSON.stringify(body) : undefined, cache:"no-store", credentials:"same-origin", redirect:"error"});
    } catch { throw {key:"Cannot connect to the server. Check your connection and try again."}; }
    let data;
    try { data = await response.json(); } catch { throw {key:"The server returned an unreadable response."}; }
    if (!response.ok || !data.ok) throw data;
    return data;
  }
  $("setup-form").addEventListener("submit", async event => {
    event.preventDefault();
    if (saving) return;
    errorData = null;
    const invalid = [...event.currentTarget.querySelectorAll("input")].filter(input => !input.closest(".acme-panel") && !input.checkValidity());
    if (invalid.length) {
      invalid.forEach(input => {
        input.setAttribute("aria-invalid", "true");
        for (let section=input.closest("details"); section; section=section.parentElement?.closest("details")) section.open=true;
      });
      invalid[0].focus();
      fail({key:invalid.some(input => input.type === "password") ? "Choose a password with at least 8 characters." : "Check the highlighted fields and try again."});
      return;
    }
    if ($("setup-password").value !== $("setup-password-confirm").value) {
      $("setup-password-confirm").setAttribute("aria-invalid", "true");
      fail({key:"Passwords do not match."});
      return;
    }
    let payload;
    try { payload = advancedEditor?.read({changedOnly:false}) || {}; }
    catch { fail({key:"Check the highlighted fields and try again."}); return; }
    for (const control of event.currentTarget.querySelectorAll("[name]")) {
      payload[control.name] = control.type === "number" ? Number(control.value) : (control.type === "password" ? control.value : control.value.trim());
    }
    payload.allow_insecure_auth = $("setup-mode").value === "local";
    if (payload.allow_insecure_auth) { payload.tls_certificate = ""; payload.tls_private_key = ""; }
    payload.ports = Object.fromEntries(Object.keys(portLabels).map(service => [service, Number($(`setup-port-${service}`).value)]));
    saving = true;
    statusKey = "Saving configuration…";
    $("setup-submit").disabled = true;
    $("setup-form").setAttribute("aria-busy", "true");
    render();
    try {
      const data = await request("POST", payload);
      token = "";
      acmeControl?.dispose();
      $("setup-token").value = "";
      advancedEditor?.clearSecrets();
      $("setup-password").value = "";
      $("setup-password-confirm").value = "";
      const destination = new URL(data.web_url);
      if (!["http:", "https:"].includes(destination.protocol) || destination.username || destination.password) throw {key:"The server returned an unreadable response."};
      $("setup-open").href = destination.href;
      const adminDestination = new URL(data.admin_url);
      if (!["http:","https:"].includes(adminDestination.protocol) || adminDestination.username || adminDestination.password) throw {key:"The server returned an unreadable response."};
      $("setup-open-admin").href = adminDestination.href;
      $("setup-form").hidden = true;
      $("setup-success").hidden = false;
      $("setup-success").scrollIntoView({block:"center", behavior:"auto"});
      statusKey = "";
    } catch (data) { statusKey = ""; fail(data); }
    finally {
      payload.admin_password = "";
      if (payload.smarthost_password) payload.smarthost_password = "";
      saving = false;
      $("setup-submit").disabled = false;
      $("setup-form").removeAttribute("aria-busy");
      render();
    }
  });
  async function unlock() {
    if (unlocking) return;
    unlocking = true;
    errorData = null;
    statusKey = "Loading setup…";
    $("setup-unlock-submit").disabled = true;
    render();
    try {
      const {defaults,schema = [],completing_existing = false} = await request("GET");
      for (const control of $("setup-form").querySelectorAll("[name]")) {
        if (control.name !== "admin_password" && Object.hasOwn(defaults,control.name)) control.value = defaults[control.name];
      }
      for (const service of Object.keys(portLabels)) $(`setup-port-${service}`).value = defaults.ports[service];
      $("setup-data-dir").readOnly = completing_existing;
      const exclude = new Set([...$("setup-form").querySelectorAll("[name]")].map(control => control.name));
      for (const field of schema) if (field.readonly) exclude.add(field.key);
      for (const service of Object.keys(portLabels)) exclude.add(`ports.${service}`);
      exclude.add("delivery_lock_port");
      exclude.add("allow_insecure_auth");
      acmeControl=PostPlusAcme.create($("setup-acme"),{domain:defaults.domain,prefix:"setup-acme",request:async(path,options={})=>{try{return await request(options.method || "GET",options.body,"/api/setup/acme"+path);}catch(data){throw new Error(data.key ? t(data.key) : PostPlusI18n.error(data));}},onCertificate:paths=>{$("setup-certificate").value=paths.tls_certificate;$("setup-key").value=paths.tls_private_key;}});
      advancedEditor = PostPlusSettings.create($("setup-advanced"),schema,defaults,{prefix:"setup-extra",exclude});
      $("setup-mode").value = defaults.allow_insecure_auth ? "local" : "tls";
      modeChanged();
      $("setup-unlock").hidden = true;
      $("setup-token").value = "";
      $("setup-form").hidden = false;
      statusKey = "";
      render();
      $("setup-domain").focus();
    } catch (data) { statusKey = ""; token = ""; fail(data); }
    finally { unlocking = false; $("setup-unlock-submit").disabled = false; }
  }
  $("setup-unlock").addEventListener("submit",event => {
    event.preventDefault();
    token = $("setup-token").value.trim();
    if (token) unlock();
  });
  render();
  if (token) unlock();
  else $("setup-token").focus();
})();
