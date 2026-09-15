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
assert.equal(chinese.error({code:"invalid_setup_token",error:"token=secret"}), "配置链接无效或已过期，请使用主程序输出的最新链接。");
assert.equal(chinese.error({error:"<script>unexpected server detail</script>"}), "请求失败，请稍后重试。");
assert.equal(chinese.error({error:"A local recipient account does not exist: user@example.com"}), "本地收件人账号不存在：user@example.com");
assert.equal(chinese.error({code:"port_unavailable"}), "服务端口不可用，请选择其他端口或检查权限。");

let checkedLabels = 0;
function translated(key, file) {
  if (["SMTP", "POP3", "IMAP"].includes(key)) return;
  assert.notEqual(chinese.t(key), key, `Missing Chinese translation in ${file}: ${key}`);
  checkedLabels++;
}
for (const file of ["index.html", "setup.html"]) {
  const html = fs.readFileSync(path.join(root, "web", file), "utf8");
  assert.match(html, /<html lang="en">/, `${file} must render in English before scripts run`);
  assert.match(html, /src="\/i18n\.js"/);
  for (const match of html.matchAll(/data-i18n(?=[\s=>])(?:="([^"]*)")?[^>]*>([^<]*)/g)) {
    const key = match[1] || match[2].trim();
    if (key) translated(key, file);
  }
  for (const match of html.matchAll(/data-i18n-(?:aria-label|title|placeholder)="([^"]+)"/g)) translated(match[1], file);
}
for (const file of ["app.js", "setup.js"]) {
  const script = fs.readFileSync(path.join(root, "web", file), "utf8");
  new vm.Script(script, {filename:file});
  for (const match of script.matchAll(/\bt\("([^"]+)"/g)) translated(match[1], file);
}
console.log(`Web checks passed: language defaults, persistence, unavailable storage, API errors, ${checkedLabels} translated labels, and script syntax.`);
