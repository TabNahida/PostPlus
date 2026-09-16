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
for (const file of ["app.js", "admin.js", "setup.js", "settings.js"]) {
  const script = fs.readFileSync(path.join(root, "web", file), "utf8");
  new vm.Script(script, {filename:file});
  for (const match of script.matchAll(/\bt\("([^"]+)"/g)) translated(match[1], file);
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
vm.runInNewContext(fs.readFileSync(path.join(root,"web/settings.js"),"utf8"),settingsSandbox);
const schema=[
  {key:"domain",group:"general",type:"text",label:"Mail domain"},
  {key:"ports.admin",group:"network",type:"number",label:"Administration port",min:1,max:65535},
  {key:"allow_insecure_auth",group:"security",type:"boolean",label:"Allow local plaintext authentication"},
  {key:"blocked_terms",group:"filter",type:"lines",label:"Blocked terms"},
  {key:"spam_rules",group:"filter",type:"json",label:"Weighted spam rules"},
  {key:"smarthost_password",group:"delivery",type:"password",label:"Outgoing relay password"},
  {key:"data_dir",group:"paths",type:"text",label:"data_dir",readonly:true}
];
const editor=settingsSandbox.window.PostPlusSettings.create(settingsRoot,schema,{
  domain:"example.com",ports:{admin:8081},allow_insecure_auth:true,blocked_terms:[],spam_rules:[],smarthost_password:"server-must-never-return-this",data_dir:"/private/mail"
},{secretStatus:{smarthost_password:true}});
function descendants(node) {return [node,...node.children.flatMap(descendants)];}
const controls=new Map(descendants(settingsRoot).filter(node=>node.dataset.configKey).map(node=>[node.dataset.configKey,node]));
const read=()=>JSON.parse(JSON.stringify(editor.read()));
assert.deepEqual(read(),{},"Opening settings cannot rewrite values or secrets");
assert.equal(controls.get("smarthost_password").value,"","Never populate secret values");
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
console.log(`Web checks passed: language defaults, persistence, API errors, ${checkedLabels} translated labels, typed settings, secret preservation, portal separation, and script syntax.`);
