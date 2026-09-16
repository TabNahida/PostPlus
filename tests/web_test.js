"use strict";
// Run with Node.js only; no browser or package installation is required.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const root = path.resolve(__dirname, "..");
const source = fs.readFileSync(path.join(root, "web/i18n.js"), "utf8");

function fixture(preference = null, unavailable = false) {
  const callbacks = new Map();
  const persisted = new Map(preference === null ? [] : [["postplus.language", preference]]);
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

const chinese = fixture("zh-CN").i18n;
assert.equal(chinese.error({error:"The email address or password is incorrect."}), "邮箱地址或密码错误。");
assert.equal(chinese.error({code:"invalid_setup_token",error:"token=secret"}), "配置密码错误或已过期，请复制终端中最新的一次性密码。");
assert.equal(chinese.error({error:"<script>unexpected server detail</script>"}), "请求失败，请稍后重试。");
assert.equal(chinese.error({error:"A local recipient account does not exist: user@example.com"}), "本地收件人账号不存在：user@example.com");
assert.equal(chinese.error({code:"port_unavailable"}), "服务端口不可用，请选择其他端口或检查权限。");
assert.equal(chinese.error({error:"Move the message to Trash before permanently deleting it."}), "请先将邮件移入已删除邮件，再将其永久删除。");

let checkedLabels = 0;
function translated(key, file) {
  if (["SMTP", "POP3", "IMAP"].includes(key)) return;
  assert.notEqual(chinese.t(key), key, `Missing Chinese translation in ${file}: ${key}`);
  checkedLabels++;
}
for (const file of ["index.html", "admin.html", "setup.html"]) {
  const html = fs.readFileSync(path.join(root, "web", file), "utf8");
  assert.match(html, /<html lang="en">/, `${file} must render in English before scripts run`);
  assert.match(html, /src="\/i18n\.js"/);
  assert.match(html, /rel="icon" href="\/favicon\.svg"/);
  for (const match of html.matchAll(/data-i18n(?=[\s=>])(?:="([^"]*)")?[^>]*>([^<]*)/g)) {
    const key = match[1] || match[2].trim();
    if (key) translated(key, file);
  }
  for (const match of html.matchAll(/data-i18n-(?:aria-label|title|placeholder)="([^"]+)"/g)) translated(match[1], file);
}
for (const file of ["app.js", "admin.js", "setup.js", "settings.js", "size.js", "acme.js"]) {
  const script = fs.readFileSync(path.join(root, "web", file), "utf8");
  new vm.Script(script, {filename:file});
  for (const match of script.matchAll(/\bt\("([^"]+)"/g)) translated(match[1], file);
  if(file==="acme.js") for(const match of script.matchAll(/\bnode\("[^"]+","([^"]+)"/g)) translated(match[1], file);
}

// Typed settings must submit only deliberate changes and preserve saved secrets.
class Control {
  constructor(tag) {
    this.tagName=tag; this.children=[]; this.dataset={}; this.value=""; this.attributes={}; this.callbacks={};
    // Native textarea.type is read-only; assigning it throws in strict scripts.
    if(tag==="textarea") Object.defineProperty(this,"type",{get:()=>"textarea"});
  }
  append(...children) {for(const child of children) {this.children.push(child); child.parent=this; child.parentElement=this;}}
  replaceChildren(...children) {this.children=[];this.append(...children);}
  setAttribute(key,value) {this.attributes[key]=value;}
  removeAttribute(key) {delete this.attributes[key];}
  addEventListener(name, callback) {this.callbacks[name]=callback;}
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
  let nextTimer=0,resolveTerms,resolveOldStatus,statusCount=0,statusResponse={ok:true,state:"idle"},termsCount=0,applied=null;
  const oldStatus=new Promise(resolve=>{resolveOldStatus=resolve;});
  const firstTerms=new Promise(resolve=>{resolveTerms=resolve;});
  const termsUrl="https://TERMS.example.test:443/legal";
  const acmeSandbox={window:{},document:{createElement:tag=>new Control(tag)},PostPlusI18n:fresh.i18n,URL,
    setTimeout(callback){const id=++nextTimer;timers.set(id,callback);return id;},clearTimeout(id){timers.delete(id);}};
  vm.runInNewContext(fs.readFileSync(path.join(root,"web/acme.js"),"utf8"),acmeSandbox);
  const component=acmeSandbox.window.PostPlusAcme.create(panelRoot,{domain:"mail.example.com",prefix:"test",onCertificate:paths=>{applied=paths;},
    async request(suffix,options){
      calls.push({suffix,options});
      if(suffix.startsWith("/terms"))return ++termsCount===1 ? firstTerms : {ok:true,terms_of_service:termsUrl};
      if(suffix==="/start")return {ok:true,job_id:"test-job",state:"queued"};
      if(suffix==="/cancel")return {ok:true,job_id:"test-job",cancel_requested:true};
      if(suffix.startsWith("/status"))return ++statusCount===1 ? oldStatus : statusResponse;
      throw new Error("Unexpected test request: "+suffix);
    }});
  const all=descendants(panelRoot),label=text=>all.find(control=>control.dataset.i18n===text),id=value=>all.find(control=>control.id===value);
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
  await tick({ok:true,job_id:"test-job",state:"succeeded",directory:"production",result:{tls_certificate:"/private/fullchain.pem",tls_private_key:"/private/key.pem",expires_at:expiresAt,staging:false}});
  const expiry=all.find(control=>control.textContent===`Certificate expires: ${expiresAt}`);
  assert.ok(expiry,"Show the expiry returned by the certificate API");
  assert.equal(expiry.hidden,false);
  assert.equal(apply.hidden,false);
  await apply.callbacks.click();
  assert.equal(applied.tls_certificate,"/private/fullchain.pem");
  assert.equal(applied.tls_private_key,"/private/key.pem");
  assert.equal(calls.some(call=>call.suffix==="/config"),false,"Issuance does not save or restart global configuration");

  await start.callbacks.click();
  await tick({ok:true,job_id:"test-job",state:"failed",code:"http_challenge_bind",error:"Port-specific details"});
  const error=all.find(control=>control.className==="form-error");
  assert.match(error.textContent,/Check the challenge port/,"Job failure handling uses the backend's code property");
  component.dispose();assert.equal(timers.size,0);
}
checkCertificateControls().then(()=>{
  console.log(`Web checks passed: language defaults, persistence, API errors, ${checkedLabels} translated labels, typed settings, exact size units, certificate controls, secret preservation, portal separation, and script syntax.`);
}).catch(error=>{console.error(error);process.exitCode=1;});
