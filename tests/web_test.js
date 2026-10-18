"use strict";
// Run with Node.js only; no browser or package installation is required.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(path.join(root, "web/i18n.js"), "utf8");

function fixture(preference = null, unavailable = false, portal = null) {
  const callbacks = new Map();
  const languageKey = portal ? `postplus.${portal}.language` : "postplus.language";
  const persisted = new Map(preference === null ? [] : [[languageKey, preference]]);
  const events = [];
  const textNode = {dataset:{i18n:"Sign in"},textContent:"Sign in"};
  const attributeNode = {
    attributes:{"data-i18n-aria-label":"Sign out"},
    getAttribute(name) { return this.attributes[name]; },
    setAttribute(name, value) { this.attributes[name] = value; }
  };
  const select = {value:"en",addEventListener(name, callback) {callbacks.set(name, callback);}};
  const document = {
    documentElement:{lang:"en"},
    querySelectorAll(selector) {
      if (selector === "[data-i18n]") return [textNode];
      if (selector === "[data-language]") return [select];
      if (selector === "[data-i18n-aria-label]") return [attributeNode];
      return [];
    },
    dispatchEvent(event) {events.push(event.type);}
  };
  const sandbox = {window:{},document,CustomEvent:class {constructor(type) {this.type=type;}},localStorage:{
    getItem(key) {if(unavailable) throw new Error("Storage unavailable"); return persisted.get(key) ?? null;},
    setItem(key,value) {if(unavailable) throw new Error("Storage unavailable"); persisted.set(key,value);}
  }};
  if (portal) sandbox.window.PostPlusPreferences = {key:name=>`postplus.${portal}.${name}`};
  vm.runInNewContext(source, sandbox, {filename:"web/i18n.js"});
  return {i18n:sandbox.window.PostPlusI18n,document,textNode,attributeNode,select,persisted,events,
    choose(language) {select.value=language;callbacks.get("change")();}};
}

const fresh = fixture();
assert.equal(fresh.i18n.language, "en", "A fresh installation must use English");
assert.equal(fresh.document.documentElement.lang, "en");
assert.equal(fresh.textNode.textContent, "Sign in");
assert.equal(fresh.persisted.size, 0, "Do not persist a browser-derived language");
fresh.choose("zh-CN");
assert.equal(fresh.textNode.textContent, "登录");
assert.equal(fresh.attributeNode.attributes["aria-label"], "退出登录");
assert.equal(fresh.document.documentElement.lang, "zh-CN");
assert.equal(fresh.persisted.get("postplus.language"), "zh-CN");
assert.deepEqual(fresh.events, ["postplus:language"]);
assert.equal(fresh.i18n.t("{count} messages", {count:7}), "7 封邮件");
assert.equal(fresh.i18n.t("Unread, {title}", {title:"<script>literal</script>"}), "未读，<script>literal</script>");
assert.equal(fresh.i18n.t("Unknown future label"), "Unknown future label");
assert.equal(fixture("zh-CN").i18n.language, "zh-CN", "An explicit choice survives reload");
assert.equal(fixture("fr").i18n.language, "en", "Unsupported preferences fall back to English");
fresh.choose("en");
assert.equal(fresh.textNode.textContent, "Sign in");
assert.equal(fresh.attributeNode.attributes["aria-label"], "Sign out");
assert.equal(fresh.document.documentElement.lang, "en");
assert.equal(fresh.persisted.get("postplus.language"), "en");
const restricted = fixture(null, true);
assert.equal(restricted.i18n.language, "en");
restricted.choose("zh-CN");
assert.equal(restricted.textNode.textContent, "登录", "Language switching works when storage is blocked");
const adminLanguage = fixture(null, false, "admin");
adminLanguage.i18n.setLanguage("zh-CN");
assert.equal(adminLanguage.persisted.get("postplus.admin.language"), "zh-CN");
assert.equal(adminLanguage.persisted.has("postplus.language"), false, "Portal language changes do not overwrite a shared preference");
assert.equal(fixture(null, false, "webmail").i18n.language, "en");

// Exercise appearance before DOMContentLoaded, when the page has no body yet.
function appearanceFixture({portal="webmail",saved=null,dark=false,unavailable=false}={}) {
  const dataset={portal},storage=new Map(saved===null ? [] : [[`postplus.${portal}.preferences`,saved]]);
  const media={matches:dark,addEventListener(name,callback){this.callback=callback;}};
  const sandbox={window:{matchMedia:()=>media},document:{documentElement:{dataset},querySelectorAll:()=>[],addEventListener(){}},localStorage:{
    getItem(key){if(unavailable)throw new Error("Storage blocked");return storage.get(key) ?? null;},
    setItem(key,value){if(unavailable)throw new Error("Storage blocked");storage.set(key,value);}
  }};
  vm.runInNewContext(fs.readFileSync(path.join(root,"web/preferences.js"),"utf8"),sandbox);
  return {api:sandbox.window.PostPlusPreferences,dataset,storage,system(value){media.matches=value;media.callback();}};
}
const appearance=appearanceFixture({dark:true});
assert.equal(appearance.dataset.theme,"dark","First paint follows the system without writing a preference");
assert.equal(appearance.storage.size,0);
appearance.system(false);assert.equal(appearance.dataset.theme,"light");
appearance.api.update({theme:"dark"});appearance.system(false);assert.equal(appearance.dataset.theme,"dark","Explicit appearance ignores system changes");
appearance.api.update({theme:"system"});assert.equal(appearance.dataset.theme,"light");
appearance.system(true);assert.equal(appearance.dataset.theme,"dark","Returning to system mode resumes live changes");
appearance.api.update({density:"compact",reading:"large",spellcheck:false});
const restored=appearanceFixture({saved:appearance.storage.get("postplus.webmail.preferences")});
assert.equal(restored.dataset.density,"compact");assert.equal(restored.dataset.reading,"large");assert.equal(restored.api.values.spellcheck,false);
const malformed=appearanceFixture({saved:'{"theme":"invalid","reading":"unexpected"}'});
assert.equal(malformed.dataset.appearance,"system");assert.equal(malformed.dataset.reading,"standard");
assert.equal(appearanceFixture({saved:"not JSON"}).dataset.appearance,"system");
const blockedAppearance=appearanceFixture({unavailable:true});blockedAppearance.api.update({theme:"dark"});assert.equal(blockedAppearance.dataset.theme,"dark");
const adminAppearance=appearanceFixture({portal:"admin"});adminAppearance.api.update({theme:"light"});
assert.equal(adminAppearance.storage.has("postplus.admin.preferences"),true);assert.equal(adminAppearance.storage.has("postplus.webmail.preferences"),false);

const chinese = fixture("zh-CN").i18n;
assert.equal(chinese.error({code:"ip_banned",permanent:true}),"登录已被封禁，请联系管理员恢复访问。");
assert.equal(chinese.error({code:"ip_banned",permanent:false,retry_after:60}),"登录暂时被封禁，请稍后重试。");
assert.equal(chinese.error({code:"ip_banned",retry_after:60}),"登录暂时被封禁，请稍后重试。","Legacy temporary ban errors remain unchanged");
assert.equal(fresh.i18n.error({code:"ip_banned",permanent:true}),"Authentication blocked. Contact the administrator to restore access.");
assert.equal(chinese.error({error:"The email address or password is incorrect."}), "邮箱地址或密码错误。");
assert.equal(chinese.error({code:"invalid_api_key",error:"private detail"}),"请检查 API 密钥名称或有效期后重试。");
assert.equal(chinese.error({code:"api_key_not_found"}),"找不到此 API 密钥，请刷新密钥列表。");
assert.equal(chinese.error({code:"api_key_limit"}),"服务器的 API 密钥数量已达上限，请检查现有密钥或联系服务器管理员。");
for(const status of ["Active","Inactive","Expired","Revoked"])assert.notEqual(chinese.t(status),status);
assert.equal(chinese.error({code:"invalid_setup_token",error:"token=secret"}), "配置密码错误或已过期，请复制终端中最新的一次性密码。");
assert.equal(chinese.error({error:"<script>unexpected server detail</script>"}), "请求失败，请稍后重试。");
assert.equal(chinese.error({error:"A local recipient account does not exist: user@example.com"}), "本地收件人账号不存在：user@example.com");
assert.equal(chinese.error({code:"port_unavailable"}), "服务端口不可用，请选择其他端口或检查权限。");
assert.equal(chinese.error({code:"invalid_configuration",field:"mail_hostname",error:"Direct delivery requires a public mail domain and mail server hostname."}),"直接投递需要公网邮箱域名与邮件服务器主机名。");
assert.equal(chinese.error({code:"dkim_not_prepared",error:"Load the current DKIM public record in the DNS guide before saving direct delivery."}),"保存直接投递配置前，请先在 DNS 向导读取当前 DKIM 公共记录。");
assert.match(chinese.error({code:"ca_tls_failed",error:"Raw OpenSSL detail"}),/系统时间和受信任根证书/);
assert.match(fresh.i18n.error({code:"ca_dns_failed",error:"Raw resolver detail"}),/DNS resolver and Internet connection/);
assert.equal(chinese.error({error:"Move the message to Trash before permanently deleting it."}), "请先将邮件移入已删除邮件，再将其永久删除。");

let checkedLabels = 0;
function translated(key, file) {
  if (["SMTP", "POP3", "IMAP"].includes(key)) return;
  assert.notEqual(chinese.t(key), key, `Missing Chinese translation in ${file}: ${key}`);
  checkedLabels++;
}
const settingsSource=fs.readFileSync(path.join(root,"src/core/settings.cpp"),"utf8");
for(const match of settingsSource.matchAll(/SettingsError\([^,]+,\s*"([^"]+)"(?=\s*[,\)])/g))translated(match[1],"settings validation");
for (const file of ["index.html", "admin.html", "setup.html"]) {
  const html = fs.readFileSync(path.join(root, "web", file), "utf8");
  assert.match(html, /<html\b[^>]*\blang="en"(?:\s|>)/, `${file} must render in English before scripts run`);
  assert.match(html, /src="\/i18n\.js"/);
  assert.match(html, /rel="icon" href="\/favicon\.svg"/);
  for (const match of html.matchAll(/data-i18n(?=[\s=>])(?:="([^"]*)")?[^>]*>([^<]*)/g)) {
    const key = match[1] || match[2].trim();
    if (key) translated(key, file);
  }
  for (const match of html.matchAll(/data-i18n-(?:aria-label|title|placeholder)="([^"]+)"/g)) translated(match[1], file);
}
for (const file of ["app.js", "admin.js", "admin-security.js", "setup.js", "settings.js", "size.js", "acme.js", "dns.js", "preferences.js", "address.js", "mail-reader.js", "mail-clients.js", "update.js", "mail-tools.js"]) {
  const script = fs.readFileSync(path.join(root, "web", file), "utf8");
  new vm.Script(script, {filename:file});
  for (const match of script.matchAll(/\bt\("([^"]+)"/g)) translated(match[1], file);
  if(file==="acme.js") for(const match of script.matchAll(/\bnode\("[^"]+","([^"]+)"/g)) translated(match[1], file);
  if(file==="admin-security.js") {
    for(const pattern of [/\bnode\("[^"]+","([^"]+)"/g,/\bbutton\("([^"]+)"/g,/\bfield\([^,]+,"[^"]+","([^"]+)"/g])for(const match of script.matchAll(pattern))translated(match[1],file);
  }
}

// Typed settings must submit only deliberate changes and preserve saved secrets.
class Control {
  constructor(tag) {
    this.tagName=tag; this.children=[]; this.dataset={}; this.value=""; this.attributes={}; this.callbacks={};
    // Native textarea.type is read-only; assigning it throws in strict scripts.
    if(tag==="textarea") Object.defineProperty(this,"type",{get:()=>"textarea"});
  }
  append(...children) {for(const child of children) {this.children.push(child); child.parent=this; child.parentElement=this;}}
  prepend(...children) {this.children.unshift(...children);for(const child of children){child.parent=this;child.parentElement=this;}}
  replaceChildren(...children) {this.children=[];this.append(...children);}
  setAttribute(key,value) {this.attributes[key]=value;}
  removeAttribute(key) {delete this.attributes[key];}
  addEventListener(name, callback) {this.listeners ||= {}; (this.listeners[name] ||= []).push(callback);this.callbacks[name]=(...args)=>{let result;for(const listener of this.listeners[name])result=listener(...args);return result;};}
  removeEventListener(name,callback) {if(this.listeners?.[name])this.listeners[name]=this.listeners[name].filter(listener=>listener!==callback);}
  closest(tag) {return this.tagName===tag ? this : this.parent?.closest(tag);}
  focus() {this.focused=true;}
  checkValidity() {return this.type!=="number" || (!this.min || Number(this.value)>=Number(this.min)) && (!this.max || Number(this.value)<=Number(this.max));}
}
const settingsRoot=new Control("div");
const settingsSandbox={window:{},document:{createElement:tag=>new Control(tag)},PostPlusI18n:fresh.i18n};
vm.runInNewContext(fs.readFileSync(path.join(root,"web/size.js"),"utf8"),settingsSandbox);
settingsSandbox.PostPlusSize=settingsSandbox.window.PostPlusSize;
vm.runInNewContext(fs.readFileSync(path.join(root,"web/settings.js"),"utf8"),settingsSandbox);
const schema=[
  {key:"domain",group:"general",type:"text",label:"Mail domain"},
  {key:"ports.admin",group:"network",type:"number",label:"Administration port",min:1,max:65535},
  {key:"allow_insecure_auth",group:"security",type:"boolean",label:"Allow local plaintext authentication"},
  {key:"blocked_terms",group:"filter",type:"lines",label:"Blocked terms"},
  {key:"spam_rules",group:"filter",type:"json",label:"Weighted spam rules"},
  {key:"smarthost_password",group:"delivery",type:"password",label:"Outgoing relay password"},
  {key:"data_dir",group:"paths",type:"text",label:"data_dir",readonly:true}
  ,{key:"max_mailbox_bytes",group:"storage",type:"number",unit:"bytes",label:"Maximum bytes per mailbox",min:1,max:2147483647,default:1073741824}
];
const editor=settingsSandbox.window.PostPlusSettings.create(settingsRoot,schema,{
  domain:"example.com",ports:{admin:8081},allow_insecure_auth:true,blocked_terms:[],spam_rules:[],smarthost_password:"server-must-never-return-this",data_dir:"/private/mail"
},{secretStatus:{smarthost_password:true}});
function descendants(node) {return [node,...node.children.flatMap(descendants)];}
const controls=new Map(descendants(settingsRoot).filter(node=>node.dataset.configKey).map(node=>[node.dataset.configKey,node]));
const read=()=>JSON.parse(JSON.stringify(editor.read()));
assert.deepEqual(read(),{},"Opening settings cannot rewrite values or secrets");
assert.equal(controls.get("smarthost_password").value,"","Never populate secret values");
const size=settingsSandbox.PostPlusSize;
for (const amount of [0,1,1023,1024,1536,1048576,1073741824,2147483647,Number.MAX_SAFE_INTEGER]) {
  const initial=size.split(amount);
  assert.equal(size.toBytes(initial.value,initial.unit),amount,"Displayed byte amounts round-trip exactly");
  const input=new Control("input"),select=new Control("select");
  const binding=size.create(input,select,amount);
  for(const unit of size.units) {
    select.value=unit.name;select.callbacks.change();
    assert.equal(binding.read(),amount,`Changing the unit to ${unit.name} must preserve exact bytes`);
  }
}
assert.equal(size.toBytes("1.5","GiB"),1610612736);
assert.equal(size.toBytes("0.0009765625","KiB"),1);
for(const [value,unit] of [["0.1","B"],["0.01","KiB"],["-1","MiB"],["1e3","B"],["9007199254740992","B"]]) assert.throws(()=>size.toBytes(value,unit));
assert.throws(()=>size.toBytes("1","KiB",2048));
assert.throws(()=>size.toBytes("3","GiB",1,2147483647));
const sizeUnit=descendants(settingsRoot).find(node=>node.id==="settings-max_mailbox_bytes-unit");
sizeUnit.value="MiB";sizeUnit.callbacks.change();
assert.deepEqual(read(),{},"Changing only the display unit does not create a configuration change");
controls.get("max_mailbox_bytes").value="1536";
assert.equal(read().max_mailbox_bytes,1610612736,"Settings submit byte integers, not display-unit amounts");
controls.get("max_mailbox_bytes").value="1024";
controls.get("ports.admin").value="9091";
controls.get("blocked_terms").value=" unwanted phrase\n\nsecond phrase ";
controls.get("allow_insecure_auth").value="false";
controls.get("data_dir").value="/attempted-change";
assert.deepEqual(read(),{ports:{admin:9091},allow_insecure_auth:false,blocked_terms:["unwanted phrase","second phrase"]});
controls.get("spam_rules").value="broken json";
assert.throws(read,/Check the value/);
assert.equal(controls.get("spam_rules").attributes["aria-invalid"],"true");
assert.equal(controls.get("spam_rules").closest("details").open,true,"Invalid advanced fields become visible");
controls.get("spam_rules").value='[{"term":"test","weight":2}]';
controls.get("ports.admin").value="8081.5";
assert.throws(read,/Check the value/);
controls.get("ports.admin").value="65536";
assert.throws(read,/Check the value/);
controls.get("ports.admin").value="8081";
controls.get("smarthost_password").value="replacement-secret";
assert.equal(read().smarthost_password,"replacement-secret");
editor.clearSecrets();
assert.equal(controls.get("smarthost_password").value,"");
assert.equal(Object.hasOwn(read(),"smarthost_password"),false);
const clearPassword=descendants(settingsRoot).find(node=>node.type==="checkbox");
clearPassword.checked=true;
clearPassword.callbacks.change();
assert.equal(read().clear_smarthost_password,true,"Clearing a saved secret requires an explicit control");
assert.equal(controls.get("smarthost_password").disabled,true);
assert.doesNotMatch(fs.readFileSync(path.join(root,"web/app.js"),"utf8"),/\/api\/admin\//,"Webmail uses only mailbox APIs");
assert.doesNotMatch(fs.readFileSync(path.join(root,"web/index.html"),"utf8"),/id="(?:admin-view|queue-body|logs-body|users-body|nav-admin)"/,"Webmail cannot include administrator panels");
assert.doesNotMatch(fs.readFileSync(path.join(root,"web/admin.html"),"utf8"),/id="compose-form"/,"Administration has its own interface");
assert.doesNotMatch(fs.readFileSync(path.join(root,"web/setup.js"),"utf8"),/(?:localStorage|sessionStorage)/,"The one-time setup password must not be persisted");

// Exercise asynchronous ACME controls with local fake responses; no CA request is sent.
async function checkCertificateControls() {
  const panelRoot=new Control("div"),timers=new Map(),calls=[];
  let nextTimer=0,resolveTerms,resolveOldStatus,statusCount=0,statusResponse={ok:true,state:"idle"},termsCount=0,applied=null,appliedMetadata=null;
  const oldStatus=new Promise(resolve=>{resolveOldStatus=resolve;});
  const firstTerms=new Promise(resolve=>{resolveTerms=resolve;});
  const termsUrl="https://TERMS.example.test:443/legal";
  const acmeSandbox={window:{},document:{createElement:tag=>new Control(tag)},PostPlusI18n:fresh.i18n,URL,
    setTimeout(callback){const id=++nextTimer;timers.set(id,callback);return id;},clearTimeout(id){timers.delete(id);}};
  vm.runInNewContext(fs.readFileSync(path.join(root,"web/acme.js"),"utf8"),acmeSandbox);
  const domains=[],running=[];
  const component=acmeSandbox.window.PostPlusAcme.create(panelRoot,{domain:"mail.example.com",prefix:"test",onDomainChange:value=>domains.push(value),onRunningChange:value=>running.push(value),onCertificate:(paths,metadata)=>{applied=paths;appliedMetadata=metadata;},
    async request(suffix,options){
      calls.push({suffix,options});
      if(suffix.startsWith("/terms"))return ++termsCount===1 ? firstTerms : {ok:true,terms_of_service:termsUrl};
      if(suffix==="/start")return {ok:true,job_id:"test-job",state:"queued"};
      if(suffix==="/cancel")return {ok:true,job_id:"test-job",cancel_requested:true};
      if(suffix.startsWith("/status"))return ++statusCount===1 ? oldStatus : statusResponse;
      throw new Error("Unexpected test request: "+suffix);
    }});
  const all=descendants(panelRoot),label=text=>all.find(control=>control.dataset.i18n===text),id=value=>all.find(control=>control.id===value);
  component.setDomain("example.com");
  assert.equal(component.getDomain(),"example.com","Untouched certificate hostname follows the mail domain");
  id("test-domain").value="mail.example.com";id("test-domain").callbacks.input();component.setDomain("new.example.com");
  assert.equal(component.getDomain(),"mail.example.com","Explicit certificate hostname survives later mail-domain edits");
  assert.deepEqual(domains,["example.com","mail.example.com"],"Notify DNS guidance when the certificate hostname changes");
  const panel=panelRoot.children[0],start=label("Request certificate"),cancel=label("Cancel request"),terms=label("Load certificate authority terms"),apply=label("Use these certificate paths"),directory=id("test-directory"),consent=all.find(control=>control.type==="checkbox");
  id("test-email").value="admin@example.com";
  panel.open=true;panel.callbacks.toggle();
  const loading=terms.callbacks.click();
  assert.equal(directory.disabled,true,"Directory cannot change while terms are loading");
  assert.equal(start.disabled,true,"Cannot request a certificate before terms load");
  resolveTerms({ok:true,terms_of_service:termsUrl});await loading;
  assert.equal(start.disabled,true,"Loading terms does not imply consent");
  consent.checked=true;consent.callbacks.change();
  assert.equal(start.disabled,false);
  await start.callbacks.click();
  assert.deepEqual(running,[false,true],"Notify the setup form to lock server identity while issuance is active");
  const submission=calls.find(call=>call.suffix==="/start").options.body;
  assert.equal(submission.terms_of_service,termsUrl,"Submit the exact terms string; URL normalization would invalidate consent");
  assert.equal(submission.directory,"staging","New certificate requests default to staging");
  resolveOldStatus({ok:true,state:"idle"});await Promise.resolve();await Promise.resolve();await Promise.resolve();
  assert.equal(start.disabled,true,"An older status response cannot replace a newly queued job");
  assert.equal(cancel.hidden,false);
  await cancel.callbacks.click();
  assert.equal(start.disabled,true,"A cancellation acknowledgement does not mean the job has stopped");
  assert.equal(cancel.hidden,false,"Continue showing an active job until its terminal status arrives");
  async function tick(response) {statusResponse=response;assert.equal(timers.size,1,"Exactly one status refresh is scheduled");const [key,callback]=timers.entries().next().value;timers.delete(key);await callback();}
  await tick({ok:true,job_id:"test-job",state:"cancelled"});
  assert.deepEqual(running,[false,true,false],"Unlock server identity after cancellation becomes terminal");
  assert.equal(start.disabled,false);
  assert.equal(cancel.hidden,true);

  await start.callbacks.click();
  await tick({ok:true,job_id:"test-job",state:"succeeded",directory:"staging",result:{tls_certificate:"/private/staging.pem",tls_private_key:"/private/staging-key.pem",staging:true}});
  assert.equal(id("test-issued-certificate").value,"/private/staging.pem","Issued paths come from the result object");
  assert.equal(apply.hidden,true,"Do not apply untrusted staging certificates to server settings");
  directory.value="production";directory.callbacks.change();
  assert.equal(consent.checked,false,"Changing certificate environment requires fresh terms consent");
  assert.equal(start.disabled,true);
  await terms.callbacks.click();consent.checked=true;consent.callbacks.change();
  await start.callbacks.click();
  const expiresAt="2026-12-15T00:00:00Z";
  await tick({ok:true,job_id:"test-job",state:"succeeded",domain:"mail.example.com",directory:"production",result:{tls_certificate:"/private/fullchain.pem",tls_private_key:"/private/key.pem",expires_at:expiresAt,staging:false}});
  const expiry=all.find(control=>control.textContent===`Certificate expires: ${expiresAt}`);
  assert.ok(expiry,"Show the expiry returned by the certificate API");
  assert.equal(expiry.hidden,false);
  assert.equal(apply.hidden,false);
  id("test-domain").value="unverified.example.com";id("test-domain").callbacks.input();
  await apply.callbacks.click();
  assert.equal(applied.tls_certificate,"/private/fullchain.pem");
  assert.equal(applied.tls_private_key,"/private/key.pem");
  assert.equal(appliedMetadata.domain,"mail.example.com","Applying a certificate uses the issued job domain, even if the hostname field was edited afterward");
  assert.equal(calls.some(call=>call.suffix==="/config"),false,"Issuance does not save or restart global configuration");

  await start.callbacks.click();
  await tick({ok:true,job_id:"test-job",state:"failed",code:"http_challenge_bind",error:"Port-specific details"});
  const error=all.find(control=>control.className==="form-error");
  assert.match(error.textContent,/Check the challenge port/,"Job failure handling uses the backend's code property");
  component.dispose();assert.equal(timers.size,0);
}
checkCertificateControls().then(checkSetupAddressFlow).then(checkSetupTlsLinks).then(checkAdminDkimControls).then(checkMaintenanceControls).then(()=>{
  console.log(`Web checks passed: language defaults, persistence, API errors, ${checkedLabels} translated labels, typed settings, exact size units, certificate controls, DNS guidance, verified certificate-host links, secret preservation, portal separation, and script syntax.`);
}).catch(error=>{console.error(error);process.exitCode=1;});

// Address inputs show the server domain and accept browser-autofilled full usernames.
const addressSandbox={window:{},PostPlusI18n:fresh.i18n};
vm.runInNewContext(fs.readFileSync(path.join(root,"web/address.js"),"utf8"),addressSandbox);
const nameInput={value:"",addEventListener(){}},domainLabel={textContent:""};
const mailbox=addressSandbox.window.PostPlusAddress.create(nameInput,domainLabel);
assert.throws(()=>mailbox.address(),/Could not load the mail domain/);
mailbox.setDomain("Example.COM");
assert.equal(domainLabel.textContent,"@example.com");
nameInput.value="Alice";assert.equal(mailbox.address(),"alice@example.com");
nameInput.value=" Alice@Example.com ";assert.equal(mailbox.address(),"alice@example.com");
assert.equal(nameInput.value,"Alice");
nameInput.value="alice@other.example";assert.throws(()=>mailbox.address(),/displayed domain/);
mailbox.setAddress("legacy@old.example");
assert.equal(nameInput.value,"legacy");assert.equal(domainLabel.textContent,"@old.example");
assert.equal(mailbox.address(),"legacy@old.example");assert.equal(nameInput.readOnly,true);
mailbox.setAddress();assert.equal(domainLabel.textContent,"@example.com");assert.equal(nameInput.readOnly,false);
assert.throws(()=>mailbox.setDomain("<img src=x>"),/unreadable response/);
nameInput.value="Alice";
mailbox.setDraftDomain(" New.EXAMPLE ");
assert.equal(domainLabel.textContent,"@new.example","Setup shows the domain as it is edited");
assert.equal(nameInput.value,"Alice","Changing the setup domain preserves the chosen mailbox name");
assert.equal(mailbox.address(),"alice@new.example");
nameInput.value=" Alice@NEW.example ";
assert.equal(mailbox.address(),"alice@new.example","Browser autofill still accepts a full address");
assert.equal(nameInput.value,"Alice");
mailbox.setDraftDomain("bad domain");
assert.throws(()=>mailbox.address(),/valid ASCII mail domain/);
mailbox.setDraftDomain("good.example");
nameInput.value="bad name";
assert.throws(()=>mailbox.address(),/displayed domain/);
console.log("Mailbox address checks passed: fixed domain, pasted addresses, foreign-domain rejection, and legacy password-reset identity.");

async function checkSetupAddressFlow() {
  const html=fs.readFileSync(path.join(root,"web/setup.html"),"utf8");
  assert.match(html,/src="\/address\.js"/);
  assert.match(html,/id="setup-admin-domain"/);
  const controls=new Map(),portNames=["smtp","pop3","imap","web","admin","auth","storage","filter","transfer","delivery_lock"];
  class SetupControl extends Control {
    constructor(tag="div"){super(tag);this.hidden=false;}
    querySelectorAll(selector){
      if(this!==id("setup-form"))return [];
      const named=["setup-domain","setup-hostname","setup-admin","setup-data-dir","setup-bind","setup-password","setup-certificate","setup-key"].map(id);
      return selector==="[name]"?named:selector==="input"?[...named,id("setup-password-confirm")]:[];
    }
    scrollIntoView(){}
  }
  function id(name){if(!controls.has(name))controls.set(name,new SetupControl());return controls.get(name);}
  for(const [control,name] of [["setup-domain","domain"],["setup-hostname","mail_hostname"],["setup-admin","admin_username"],["setup-data-dir","data_dir"],["setup-bind","bind"],["setup-password","admin_password"],["setup-certificate","tls_certificate"],["setup-key","tls_private_key"]])id(control).name=name;
  id("setup-password").type="password";
  id("setup-password-confirm").type="password";
  id("setup-mode").value="local";
  const ports=Object.fromEntries(portNames.map((service,index)=>[service,2500+index]));
  const defaults={domain:"localhost",admin_username:"admin@localhost",data_dir:"/srv/postplus",bind:"127.0.0.1",allow_insecure_auth:true,outbound_mode:"disabled",ports};
  const requests=[];
  let certificateHost="localhost",certificateChanged;
  const languageCallbacks=new Map();
  const sandbox={window:{},document:{getElementById:id,createElement:tag=>new SetupControl(tag),addEventListener:(name,callback)=>languageCallbacks.set(name,callback),title:""},
    PostPlusI18n:fresh.i18n,PostPlusAddress:addressSandbox.window.PostPlusAddress,
    PostPlusAcme:{create:(_root,options)=>{certificateChanged=options.onDomainChange;return {dispose(){},translate(){},getDomain:()=>certificateHost,setDomain:value=>{certificateHost=value;certificateChanged?.();}};}},PostPlusSettings:{create:()=>({read:()=>({}),clearSecrets(){},highlight(){},translate(){}})},
    URL,URLSearchParams,location:{hash:"#token=secret",pathname:"/setup",search:""},history:{replaceState(){}},
    fetch:async(route,options)=>{requests.push({route,options});return {ok:true,json:async()=>options.method==="POST"?{ok:true,web_url:"http://localhost:8080/",admin_url:"http://localhost:8081/"}:{ok:true,defaults,schema:[]}};}};
  vm.runInNewContext(fs.readFileSync(path.join(root,"web/dns.js"),"utf8"),sandbox);
  sandbox.PostPlusDns=sandbox.window.PostPlusDns;
  vm.runInNewContext(fs.readFileSync(path.join(root,"web/mail-clients.js"),"utf8"),sandbox);
  sandbox.PostPlusMailClients=sandbox.window.PostPlusMailClients;
  vm.runInNewContext(fs.readFileSync(path.join(root,"web/setup.js"),"utf8"),sandbox);
  for(let index=0;index<12;index++)await Promise.resolve();
  assert.equal(id("setup-admin").value,"admin","The setup default is shown as a mailbox name");
  assert.equal(id("setup-admin-domain").textContent,"@localhost");
  assert.equal(id("setup-hostname").value,"","Local names have no default public mail hostname");
  id("setup-domain").value="Example.COM";id("setup-domain").callbacks.input();
  assert.equal(id("setup-admin-domain").textContent,"@example.com","The suffix tracks a changed setup domain");
  assert.equal(id("setup-admin").value,"admin");
  assert.equal(id("setup-hostname").value,"mail.example.com","Use an independent mail subdomain by default");
  assert.equal(certificateHost,"mail.example.com","The built-in certificate uses the server hostname");
  id("setup-hostname").value="smtp.example.com";id("setup-hostname").callbacks.input();
  id("setup-domain").value="team.example.com";id("setup-domain").callbacks.input();
  assert.equal(id("setup-hostname").value,"smtp.example.com","Preserve a manually chosen hostname");
  id("setup-domain").value="Example.COM";id("setup-domain").callbacks.input();
  id("setup-password").value="test-passphrase";id("setup-password-confirm").value="test-passphrase";
  id("setup-admin").value="alice@wrong.example";
  await id("setup-form").callbacks.submit({preventDefault(){},currentTarget:id("setup-form")});
  assert.equal(requests.filter(call=>call.options.method==="POST").length,0,"A different domain cannot reach setup submission");
  id("setup-admin").value="Alice@EXAMPLE.COM";
  await id("setup-form").callbacks.submit({preventDefault(){},currentTarget:id("setup-form")});
  const posted=requests.find(call=>call.options.method==="POST");
  assert.ok(posted,"Setup submits with an address on the selected domain");
  assert.equal(JSON.parse(posted.options.body).admin_username,"alice@example.com");
  assert.equal(id("setup-admin").value,"Alice","Browser autofill is normalized to the mailbox name");
}

async function checkSetupTlsLinks() {
  async function run({bind="0.0.0.0",replaceCertificate=false,changedHostname=false,direct=false,expected="https://mail.example.com:8080/"}={}) {
    const controls=new Map(),requests=[];let acmeOptions,certificateHost="example.com";
    class SetupControl extends Control {
      querySelectorAll(selector) {
        if(this!==id("setup-form"))return [];
        const named=["setup-domain","setup-hostname","setup-admin","setup-data-dir","setup-bind","setup-password","setup-certificate","setup-key"].map(id);
        return selector==="[name]"?named:selector==="input"?[...named,id("setup-password-confirm")]:[];
      }
      scrollIntoView(){}
    }
    function id(name){if(!controls.has(name))controls.set(name,new SetupControl("div"));return controls.get(name);}
    for(const [control,name] of [["setup-domain","domain"],["setup-hostname","mail_hostname"],["setup-admin","admin_username"],["setup-data-dir","data_dir"],["setup-bind","bind"],["setup-password","admin_password"],["setup-certificate","tls_certificate"],["setup-key","tls_private_key"]])id(control).name=name;
    id("setup-password").type="password";id("setup-password-confirm").type="password";
    const defaults={domain:"example.com",admin_username:"admin@example.com",data_dir:"/srv/postplus",bind,allow_insecure_auth:false,outbound_mode:direct?"direct":"disabled",ports:Object.fromEntries(["smtp","pop3","imap","web","admin","auth","storage","filter","transfer","delivery_lock"].map((service,index)=>[service,2500+index]))};
    const webUrl=["0.0.0.0","::"].includes(bind)?"https://example.com:8080/":`https://${bind}:8080/`;
    const sandbox={window:{},document:{getElementById:id,createElement:tag=>new SetupControl(tag),addEventListener(){}},
      PostPlusI18n:fresh.i18n,PostPlusAddress:addressSandbox.window.PostPlusAddress,
      PostPlusAcme:{create:(_root,options)=>{acmeOptions=options;return {dispose(){},translate(){},getDomain:()=>certificateHost,setDomain:value=>{certificateHost=value;}};}},
      PostPlusSettings:{create:()=>({read:()=>({}),clearSecrets(){},highlight(){},translate(){}})},URL,URLSearchParams,
      location:{hash:"#token=test",pathname:"/setup",search:""},history:{replaceState(){}},
      fetch:async(route,options)=>{requests.push({...options,route});return {ok:true,json:async()=>route==="/api/setup/dkim"?{ok:true,domain:"example.com",selector:"postplus",name:"postplus._domainkey.example.com",type:"TXT",value:"v=DKIM1; k=rsa; h=sha256; p="+"A".repeat(392),fingerprint:"public-key-fingerprint"}:options.method==="POST"?{ok:true,web_url:webUrl,admin_url:"https://localhost:8081/"}:{ok:true,defaults,schema:[]}};}};
    vm.runInNewContext(fs.readFileSync(path.join(root,"web/dns.js"),"utf8"),sandbox);
    sandbox.PostPlusDns=sandbox.window.PostPlusDns;
    vm.runInNewContext(fs.readFileSync(path.join(root,"web/mail-clients.js"),"utf8"),sandbox);
    sandbox.PostPlusMailClients=sandbox.window.PostPlusMailClients;
    vm.runInNewContext(fs.readFileSync(path.join(root,"web/setup.js"),"utf8"),sandbox);
    for(let index=0;index<12;index++)await Promise.resolve();
    assert.equal(id("setup-acme").hidden,true,"Existing PEM certificates do not present a public-port-80 requirement");
    id("setup-certificate-method").value="http01";id("setup-certificate-method").callbacks.change();
    assert.equal(id("setup-acme").hidden,false);assert.equal(id("setup-existing-help").hidden,true);
    acmeOptions.onRunningChange(true);assert.equal(id("setup-hostname").disabled,true);assert.equal(id("setup-domain").disabled,true);
    acmeOptions.onRunningChange(false);assert.equal(id("setup-hostname").disabled,false);
    acmeOptions.onCertificate({tls_certificate:"/private/mail/fullchain.pem",tls_private_key:"/private/mail/key.pem"},{domain:"mail.example.com"});
    certificateHost="unverified.example.com";
    if(replaceCertificate)id("setup-certificate").value="/private/manual/fullchain.pem";
    id("setup-password").value="test-passphrase";id("setup-password-confirm").value="test-passphrase";
    if(direct){
      await id("setup-form").callbacks.submit({preventDefault(){},currentTarget:id("setup-form")});
      assert.equal(requests.filter(call=>call.method==="POST").length,0,"Direct setup cannot submit before current DKIM key exists");
      assert.match(id("setup-error").textContent,/current domain and selector/);
      const generate=descendants(id("setup-dns-guide")).find(control=>control.id==="setup-dns-generate-dkim");await generate.callbacks.click();
      assert.equal(requests.at(-1).route,"/api/setup/dkim");assert.deepEqual(JSON.parse(requests.at(-1).body),{domain:"example.com",selector:"postplus"});
    }
    if(changedHostname){
      id("setup-hostname").value="unverified.example.com";id("setup-hostname").callbacks.input();
      await id("setup-form").callbacks.submit({preventDefault(){},currentTarget:id("setup-form")});
      assert.equal(requests.filter(options=>options.method==="POST").length,0,"A certificate for the old hostname cannot silently be saved for a newly requested hostname");
      assert.match(id("setup-error").textContent,/issued for mail.example.com/);
      id("setup-hostname").value="mail.example.com";id("setup-hostname").callbacks.input();
    }
    await id("setup-form").callbacks.submit({preventDefault(){},currentTarget:id("setup-form")});
    assert.equal(id("setup-open").href,expected,"Webmail URL uses only the certificate domain known for matching saved paths and a wildcard bind");
    if(direct){const posted=JSON.parse(requests.find(call=>call.route==="/api/setup"&&call.method==="POST").body);assert.equal(posted.outbound_mode,"direct");assert.equal(posted.dkim_selector,"postplus");assert.equal(posted.dkim_fingerprint,"public-key-fingerprint");assert.equal(posted.mail_hostname,"mail.example.com");assert.equal(posted.dkim_private_key,undefined);}
    assert.equal(id("setup-open-admin").href,"https://localhost:8081/","Administration stays on its local listener");
    if(!replaceCertificate)assert.match(id("setup-access-help").textContent,/SSH tunnel.*mail.example.com/);
  }
  await run();
  await run({direct:true});
  await run({bind:"::"});
  await run({changedHostname:true});
  await run({replaceCertificate:true,expected:"https://example.com:8080/"});
  await run({bind:"192.0.1.2",expected:"https://192.0.1.2:8080/"});
}

async function checkAdminDkimControls(){
  const fields=[{key:"domain",group:"general",type:"text",label:"Mail domain"},{key:"outbound_mode",group:"delivery",type:"select",options:["disabled","direct","relay"],label:"Outgoing delivery mode"},{key:"dkim_selector",group:"delivery",type:"text",label:"DKIM selector"},{key:"dkim_private_key",group:"delivery",type:"text",readonly:true,label:"DKIM private key file"}];
  const response=({domain,selector})=>({ok:true,domain,selector,name:selector+"._domainkey."+domain,type:"TXT",value:"v=DKIM1; k=rsa; h=sha256; p="+"A".repeat(392),fingerprint:"public-fingerprint"});
  function create({mode="disabled",savedKey="",generateDkim=async body=>response(body)}={}){
    const root=new Control("div"),calls=[],editor=settingsSandbox.window.PostPlusSettings.create(root,fields,{domain:"example.com",outbound_mode:mode,dkim_selector:"postplus",dkim_private_key:savedKey},{prefix:"admin-test",generateDkim:body=>{calls.push(JSON.parse(JSON.stringify(body)));return generateDkim(body);}});
    const all=()=>descendants(root),control=key=>all().find(item=>item.dataset.configKey===key),button=all().find(item=>item.id==="admin-test-generate-dkim");return {root,calls,editor,all,control,button};
  }
  const f=create();assert.deepEqual(JSON.parse(JSON.stringify(f.editor.read())),{});assert.equal(f.all().find(item=>item.className==="settings-dkim").hidden,true);
  f.control("outbound_mode").value="direct";f.control("outbound_mode").callbacks.change();assert.throws(()=>f.editor.read(),/current domain and selector/);
  await f.button.callbacks.click();assert.deepEqual(f.calls,[{domain:"example.com",selector:"postplus"}]);
  assert.deepEqual(JSON.parse(JSON.stringify(f.editor.read())),{outbound_mode:"direct"});
  assert.equal(f.all().find(item=>item.readOnly&&item.attributes["aria-label"]==="Full DNS name").value,"postplus._domainkey.example.com");
  assert.equal(f.all().find(item=>item.readOnly&&item.attributes["aria-label"]==="Value / content").value,response({domain:"example.com",selector:"postplus"}).value);
  f.control("dkim_selector").value="updated";f.control("dkim_selector").callbacks.input();assert.throws(()=>f.editor.read(),/current domain and selector/);assert.equal(f.all().filter(item=>item.readOnly).length,0);
  const deferred=[];const race=create({mode:"direct",generateDkim:()=>new Promise(resolve=>deferred.push(resolve))});
  const loading=race.button.callbacks.click();race.control("domain").value="other.example.com";race.control("domain").callbacks.input();deferred[0](response({domain:"example.com",selector:"postplus"}));await loading;
  assert.throws(()=>race.editor.read(),/current domain and selector/);assert.equal(race.all().filter(item=>item.readOnly).length,0,"Changed-domain response does not export old record");
  const saved=create({mode:"direct",savedKey:"/srv/private/dkim.pem"});assert.deepEqual(JSON.parse(JSON.stringify(saved.editor.read())),{},"Existing unchanged direct config retains managed key");
  saved.control("dkim_selector").value="new";saved.control("dkim_selector").callbacks.input();assert.throws(()=>saved.editor.read(),/current domain and selector/);
  const malformed=create({mode:"direct",generateDkim:async body=>({...response(body),private_key:"never export"})});await malformed.button.callbacks.click();assert.throws(()=>malformed.editor.read());assert.equal(malformed.all().filter(item=>item.readOnly).length,0);
  const disposed=create({mode:"direct",generateDkim:()=>new Promise(resolve=>deferred.push(resolve))});const stale=disposed.button.callbacks.click();disposed.editor.dispose();deferred[1](response({domain:"example.com",selector:"postplus"}));await stale;assert.equal(disposed.all().filter(item=>item.readOnly).length,0);
}

async function checkMaintenanceControls() {
  const controls=new Map(),calls=[],timers=new Map();let timerId=0;
  class AdminControl extends Control {
    constructor(tag="div"){super(tag);this.classList={toggle(){},add(){},remove(){}};this.hidden=false;}
    querySelector(){return id("submit-button");}
    querySelectorAll(){return [];}
    reset(){}
    showModal(){this.open=true;}
    close(){this.open=false;}
    scrollIntoView(){}
  }
  function id(name){if(!controls.has(name))controls.set(name,new AdminControl());return controls.get(name);}
  const sandbox={window:{},document:{getElementById:id,querySelectorAll:()=>[],addEventListener(){},createElement:tag=>new AdminControl(tag),createDocumentFragment:()=>new AdminControl("fragment"),title:""},
    PostPlusI18n:fresh.i18n,PostPlusAddress:addressSandbox.window.PostPlusAddress,PostPlusPreferences:{closeNavigation(){}},
    PostPlusMailReader:{create:()=>({show(){},clear(){},dispose(){}})},
    URL,URLSearchParams,TextEncoder,location:{origin:"http://localhost:8081"},
    setTimeout(callback){const key=++timerId;timers.set(key,callback);return key;},clearTimeout:key=>timers.delete(key),
    fetch:async route=>({ok:route==="/api/public/config",status:route==="/api/public/config"?200:401,
      json:async()=>route==="/api/public/config"?{ok:true,domain:"localhost"}:{ok:false}})};
  vm.createContext(sandbox);vm.runInContext(fs.readFileSync(path.join(root,"web/admin.js"),"utf8"),sandbox);
  for(let index=0;index<12;index++)await Promise.resolve();
  sandbox.request=async(route,options)=>{calls.push({route,options});return {ok:true,restart_required:true,admin_url:"http://localhost:8081/",web_url:"http://localhost:8080/"};};
  vm.runInContext('api=request;state.user={username:"admin@localhost",admin:true,csrf:"test"};settingsData={revision:1};settingsEditor={read:()=>({domain:"example.com"}),clearSecrets(){},highlight(){}};',sandbox);
  id("settings-form").hidden=false;
  id("shutdown-form").callbacks.submit({preventDefault(){},currentTarget:id("shutdown-form")});
  for(let index=0;index<12;index++)await Promise.resolve();
  assert.deepEqual(calls.map(call=>call.route),["/api/admin/config","/api/admin/shutdown"],"Shutdown first commits changed settings");
  assert.equal(calls[0].options.body.apply,false,"Shutdown saves without scheduling a competing automatic restart");
  assert.equal(id("shutdown-open").disabled,true);assert.match(id("shutdown-status").textContent,/Shutdown requested/);
  calls.length=0;id("settings-form").hidden=false;
  vm.runInContext('shutdownPending=false;settingsEditor.read=()=>{throw new Error("Invalid port");};',sandbox);
  id("shutdown-form").callbacks.submit({preventDefault(){},currentTarget:id("shutdown-form")});
  for(let index=0;index<12;index++)await Promise.resolve();
  assert.equal(calls.length,0,"Invalid settings prevent the shutdown request");
  assert.match(id("shutdown-error").textContent,/Invalid port/);
  let state="running";
  sandbox.request=async(route)=>{calls.push({route});return route==="/api/admin/backup"?{ok:true,job_id:"test-backup"}:{ok:true,state,download_url:"/api/admin/backup/download?job_id=test-backup"};};
  vm.runInContext('api=request;',sandbox);
  await id("backup-create").callbacks.click();
  assert.equal(id("backup-create").disabled,true);assert.equal(timers.size,1);
  state="complete";const [key,poll]=timers.entries().next().value;timers.delete(key);await poll();
  assert.equal(id("backup-download").hidden,false);assert.equal(id("backup-create").disabled,false);
  assert.equal(id("backup-download").href,"http://localhost:8081/api/admin/backup/download?job_id=test-backup");
  assert.match(id("backup-status").textContent,/Backup ready/);
  calls.length=0;
  sandbox.request=async(route,options)=>{calls.push({route,options});return {ok:true,username:"admin@localhost",admin:true};};
  vm.runInContext('api=request;signedIn=async()=>{};',sandbox);
  id("login-email").value="Admin@LOCALHOST";id("login-password").value="test-password";
  assert.equal(id("login-domain").textContent,"@localhost");
  id("login-form").callbacks.submit({preventDefault(){},currentTarget:id("login-form")});
  for(let index=0;index<8;index++)await Promise.resolve();
  assert.equal(calls[0].route,"/api/login");
  assert.equal(calls[0].options.body.username,"admin@localhost","Administrator login reconstructs the configured domain");
  assert.equal(id("login-email").value,"Admin","Full address autofill leaves only the mailbox name visible");
  calls.length=0;id("login-email").value="admin@other.example";
  id("login-form").callbacks.submit({preventDefault(){},currentTarget:id("login-form")});
  for(let index=0;index<8;index++)await Promise.resolve();
  assert.equal(calls.length,0,"Administrator login rejects a different domain before requesting authentication");
  assert.match(id("login-error").textContent,/displayed domain/);
  calls.length=0;
  const customFolder="Projects/客户",literalFolder="<img src=x>";
  sandbox.request=async route=>{calls.push({route});return route.startsWith("/api/admin/folders?") ? {folders:[{name:"INBOX"},{name:customFolder},{name:literalFolder}]} : {messages:[]};};
  vm.runInContext('api=request;inspectUsername="user+tag@localhost";',sandbox);
  id("inspect-folder").value="all";
  await vm.runInContext('loadInspection()',sandbox);
  assert.equal(calls.length,4,"All folders inspects every discovered selectable folder");
  assert.ok(calls.some(call=>call.route.includes("folder="+encodeURIComponent(customFolder))));
  assert.ok(calls.every(call=>call.route.includes("username=user%2Btag%40localhost")));
  assert.deepEqual(id("inspect-folder").children.map(option=>option.value),["all","INBOX",customFolder,literalFolder]);
  assert.equal(id("inspect-folder").children.at(-1).textContent,literalFolder,"Custom folder labels remain literal text");
}
