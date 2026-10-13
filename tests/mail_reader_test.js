"use strict";
// Dependency-free component checks use parsed DOM fixtures. Actual HTML parsing
// and zero-request tracking checks also run in mail_reader_browser.html.
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
const root=path.resolve(__dirname,".."),source=fs.readFileSync(path.join(root,"web/mail-reader.js"),"utf8");
const descendants=node=>node.children.flatMap(child=>[child,...descendants(child)]);
class Element {
  constructor(tag="div",attrs={},children=[]) {
    this.nodeType=1;this.tagName=tag.toUpperCase();this.localName=tag;this.namespaceURI="http://www.w3.org/1999/xhtml";this.children=children;this.childNodes=children;this.attributes={...attrs};this.events={};this.dataset={};this.text="";
    const entries=Object.entries(attrs.styles || {});this.style={length:entries.length,item:i=>entries[i][0],getPropertyValue:key=>attrs.styles[key]};
  }
  append(...nodes){this.children.push(...nodes);this.childNodes=this.children;}
  prepend(...nodes){this.children.unshift(...nodes);this.childNodes=this.children;}
  replaceChildren(...nodes){this.children=[];this.append(...nodes);}
  setAttribute(name,value){this.attributes[name]=String(value);}
  getAttribute(name){return this.attributes[name]??null;}
  addEventListener(name,callback){this.events[name]=callback;}
  fire(name){return this.events[name]?.();}
  set textContent(value){this.text=String(value);this.children=[];this.childNodes=this.children;}
  get textContent(){return this.text+this.children.map(child=>child.textContent).join("");}
}
const text=value=>({nodeType:3,textContent:value,children:[]});
const e=(tag,attrs={},...children)=>new Element(tag,attrs,children.map(child=>typeof child==="string"?text(child):child));
const png=Buffer.from("\x89PNG\r\n\x1a\n","binary").toString("base64");
const fixtures=new Map([
  ["attack",[e("script",{},"parent.stolen=true"),e("style",{},"@import 'https://tracker.invalid'"),e("iframe",{src:"https://tracker.invalid"}),e("form",{action:"https://tracker.invalid"},e("input",{name:"secret"})),e("svg",{},e("script",{},"alert(1)")),e("math",{},"unsafe"),e("object",{data:"https://tracker.invalid"}),e("p",{onclick:"steal()",id:"app-screen",class:"sender",styles:{color:"rgb(12, 34, 56)","font-size":"22px","background-color":"#ffffff","background-image":"url(https://tracker.invalid)",position:"fixed",inset:"0","--secret":"url(https://tracker.invalid)",margin:"8px",padding:"12px","border-radius":"4px","font-family":"Arial",width:"100%","text-align":"center",display:"block","text-indent":"var(--secret)"}},"Readable <验证码>",e("a",{href:"javascript:alert(1)",onclick:"bad()"},"bad link"),e("a",{href:"https://example.com/path?x=1&y=2",target:"_self",ping:"https://tracker.invalid"},"safe link")),e("img",{src:"https://tracker.invalid/pixel",srcset:"https://tracker.invalid/other 2x",onerror:"alert(1)",alt:"tracking"})]],
  ["html-only",[e("h2",{},"验证码 123456"),e("p",{},"Line one",e("br"),"Line two")]],
  ["cid",[e("img",{src:"cid:logo%40example",alt:"logo"}),e("img",{src:"cid:svg",alt:"svg"}),e("img",{src:"data:image/svg+xml;base64,PHN2Zy8+",alt:"raw svg"}),e("img",{src:`data:image/png;base64,${png}`,alt:"safe embedded"})]],
  ["encoded-links",[e("a",{href:"java\nscript:alert(1)"},"newline"),e("a",{href:"https://username:password@example.com"},"credentials"),e("a",{href:"/api/admin/messages"},"relative"),e("a",{href:"data:text/html,<script>alert(1)</script>"},"data"),e("a",{href:"mailto:person@example.com"},"email")]],
  ["table",[e("table",{},e("tr",{},e("td",{colspan:"2",rowspan:"9999",styles:{width:"600px","border-color":"#333"}},"A"),e("td",{},"B")))]]
]);
function fixture() {
  const callbacks=new Map(),created=[];
  const document={documentElement:{dataset:{theme:"dark",reading:"large"}},
    createElement(tag){const node=new Element(tag);created.push(node);if(tag==="template")Object.defineProperty(node,"innerHTML",{set(value){assert.equal(created.includes(node),true);node.content={childNodes:fixtures.get(value)||[text(value)]};}});return node;},
    addEventListener(name,callback){callbacks.set(name,callback);},removeEventListener(name,callback){if(callbacks.get(name)===callback)callbacks.delete(name);}};
  const sandbox={window:{},document,URL,location:{href:"https://mail.example.com/"},PostPlusI18n:{language:"en",t:key=>key},atob:value=>Buffer.from(value,"base64").toString("binary"),DOMParser:class{constructor(){throw new Error("Raw HTML must not use a resource-capable DOMParser document");}}};
  vm.runInNewContext(source,sandbox,{filename:"mail-reader.js"});const api=sandbox.window.PostPlusMailReader,container=new Element();return {api,container,component:api.create(container),callbacks,created,sandbox};
}
const f=fixture();const attack=f.api.sanitize("attack");
assert.match(attack.html,/Readable &lt;验证码&gt;/);assert.equal(attack.remoteImages,1);
assert.doesNotMatch(attack.html,/<(?:script|style|iframe|form|input|svg|math|object)\b|onclick=|onerror=|srcset=|ping=|javascript:|position:|background-image:|--secret/);
assert.match(attack.html,/color:rgb\(12, 34, 56\)/);assert.match(attack.html,/font-size:22px/);assert.match(attack.html,/padding:12px/);assert.match(attack.html,/text-align:center/);
assert.match(attack.html,/target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer"/);assert.match(attack.html,/href="https:\/\/example.com\/path\?x=1&amp;y=2"/);
assert.doesNotMatch(attack.html,/<img[^>]+https:/);assert.match(attack.html,/mail-image-placeholder/);
assert.match(f.api.sanitize("attack",{loadRemoteImages:true}).html,/<img[^>]+src="https:\/\/tracker.invalid\/pixel"/);
const links=f.api.sanitize("encoded-links");assert.equal((links.html.match(/href=/g)||[]).length,1);assert.match(links.html,/href="mailto:person@example.com"/);
const cid=f.api.sanitize("cid",{inlineImages:[{cid:"<logo@example>",content_type:"image/png",data:png},{cid:"svg",content_type:"image/svg+xml",data:"PHN2Zy8+"}]});
assert.equal((cid.html.match(/src="data:image\/png/g)||[]).length,2);assert.doesNotMatch(cid.html,/src="[^" ]*svg/);
assert.doesNotMatch(f.api.sanitize("cid",{inlineImages:[{cid:"logo@example",content_type:"image/png",data:"PHN2Zy8+"}]}).html,/src="data:image\/png[^>]+alt="logo"/,"Raster MIME alone cannot admit SVG bytes");
assert.match(f.api.sanitize("table").html,/colspan="2"/);assert.doesNotMatch(f.api.sanitize("table").html,/rowspan=/);assert.match(f.api.sanitize("html-only").text,/验证码 123456\n+Line one\nLine two/);
f.component.show({html:"attack",text:"Plain fallback",forwarded:[{subject:"Nested <subject>",from:"Sender <sender@example.com>",to:"reader@example.com",date:"Today",html:"html-only",text:"",forwarded:[{subject:"Deep forward",text:"Nested plain"}]}]});
let all=descendants(f.container),frames=all.filter(node=>node.tagName==="IFRAME");assert.equal(frames.length,2);
for(const frame of frames){assert.equal(frame.attributes.sandbox,"allow-popups allow-popups-to-escape-sandbox");assert.doesNotMatch(frame.attributes.sandbox,/allow-scripts|allow-same-origin/);assert.match(frame.srcdoc,/script-src &#39;none&#39;/);assert.match(frame.srcdoc,/style-src https:\/\/mail.example.com &#39;unsafe-inline&#39;/);assert.match(frame.srcdoc,/img-src data:;/);assert.match(frame.srcdoc,/data-theme="dark" data-reading="large"/);assert.equal(frame.attributes.referrerpolicy,"no-referrer");}
assert.ok(all.some(node=>node.className==="forwarded-subject"&&node.textContent==="Nested <subject>"));assert.ok(all.some(node=>node.tagName==="DD"&&node.textContent==="Sender <sender@example.com>"));
all.find(node=>node.tagName==="BUTTON"&&node.textContent==="Show plain text").fire("click");all=descendants(f.container);assert.equal(all.filter(node=>node.tagName==="IFRAME").length,0);assert.ok(all.some(node=>node.tagName==="PRE"&&node.textContent.includes("验证码 123456")),"HTML-only messages have a readable plain-text fallback");
all.find(node=>node.tagName==="BUTTON"&&node.textContent==="Show formatted message").fire("click");all=descendants(f.container);all.find(node=>node.tagName==="BUTTON"&&node.textContent==="Load remote images").fire("click");frames=descendants(f.container).filter(node=>node.tagName==="IFRAME");assert.match(frames[0].srcdoc,/img-src data: https: http:/);
f.component.show({html:"attack"});frames=descendants(f.container).filter(node=>node.tagName==="IFRAME");assert.match(frames[0].srcdoc,/img-src data:;/,"A different message resets image consent");assert.doesNotMatch(frames[0].srcdoc,/<img[^>]+https:/);
f.component.clear();assert.equal(f.container.children.length,0);f.callbacks.get("postplus:language")();assert.equal(f.container.children.length,0,"Translation cannot restore cleared content");
const cycle={text:"One"};cycle.forwarded=[cycle];f.component.show(cycle);assert.equal(descendants(f.container).filter(node=>node.className==="mail-reader-message").length,1);f.component.dispose();assert.equal(f.container.children.length,0);assert.equal(f.callbacks.has("postplus:language"),false);
for(const [portal,app,prefix] of [["index.html","app.js","message"],["admin.html","admin.js","inspect"]]) {
  const html=fs.readFileSync(path.join(root,"web",portal),"utf8"),script=fs.readFileSync(path.join(root,"web",app),"utf8");
  assert.equal((html.match(/src="\/mail-reader\.js"/g)||[]).length,1);assert.ok(html.indexOf('/mail-reader.js')<html.indexOf('/'+app));assert.match(html,new RegExp(`<div id="${prefix}-body"`));assert.match(script,/Reader\.show\(preview\)/);assert.match(script,/Reader\.clear\(\)/);
}
(async()=>{
  const {fixture:adminFixture}=require("./api_keys_ui_test.js");
  const admin=adminFixture();await admin.ready();const adminReader=admin.run("inspectionReader"),adminShown=[];let adminCleared=0;
  adminReader.show=value=>adminShown.push(value);adminReader.clear=()=>{adminCleared++;};
  admin.respond(()=>({ok:true,message:{subject:"Current",text:"",html:"<p>Private mail</p>",forwarded:[]},raw:"private raw"}));
  admin.run('inspectUsername="user@example.com";');await admin.run('inspectMessage({id:"one",folder:"INBOX"})');assert.equal(adminShown.length,1);
  admin.respond(()=>({ok:true,messages:[]}));await admin.run("loadInspection()");assert.equal(admin.id("inspect-raw").textContent,"");assert.equal(admin.id("inspect-content").hidden,true);assert.ok(adminCleared>=2);
  let finishAdmin;admin.sandbox.fetch=async()=>({ok:true,status:200,json:()=>new Promise(resolve=>{finishAdmin=resolve;})});
  const adminPending=admin.run('inspectMessage({id:"late",folder:"INBOX"})');for(let i=0;i<6;i++)await Promise.resolve();admin.run("signedOut()");finishAdmin({ok:true,message:{html:"<p>Stale private mail</p>"},raw:"stale raw"});await adminPending;
  assert.equal(adminShown.length,1,"A stale inspection response cannot redisplay private mail after logout");assert.equal(admin.id("inspect-raw").textContent,"");
  const web=adminFixture();const webShown=[];let webCleared=0;const webSandbox={...web.sandbox,window:{},
    document:{...web.sandbox.document,querySelector:selector=>web.id(selector)},PostPlusMailReader:{create:()=>({show:value=>webShown.push(value),clear:()=>{webCleared++;}})}};
  vm.createContext(webSandbox);vm.runInContext(fs.readFileSync(path.join(root,"web/app.js"),"utf8"),webSandbox);for(let i=0;i<12;i++)await Promise.resolve();
  const webRun=code=>vm.runInContext(code,webSandbox);webRun('state.user={username:"reader@example.com",csrf:"test"};');
  webSandbox.fetch=async()=>({ok:true,status:200,json:async()=>({ok:true,message:{subject:"Current",text:"Plain",html:"<p>Private HTML</p>",inline_images:[{cid:"secret",data:png}]},raw:"private raw"})});
  await webRun('openMessage("one")');assert.equal(webShown.length,1);assert.equal(webRun('Object.hasOwn(state.previews.get("one"),"html")'),false);assert.equal(webRun('Object.hasOwn(state.previews.get("one"),"inline_images")'),false,"List cache cannot retain inline image payloads");
  webRun("clearReader()");assert.equal(web.id("message-raw").textContent,"");assert.equal(web.id("reader-content").hidden,true);assert.ok(webCleared>=2);
  let finishWeb;webSandbox.fetch=async()=>({ok:true,status:200,json:()=>new Promise(resolve=>{finishWeb=resolve;})});
  const webPending=webRun('openMessage("late")');for(let i=0;i<6;i++)await Promise.resolve();webRun("signedOut()");finishWeb({ok:true,message:{html:"<p>Stale private mail</p>"},raw:"stale raw"});await webPending;
  assert.equal(webShown.length,1,"A stale Webmail response cannot redisplay private mail after logout");assert.equal(web.id("message-raw").textContent,"");
  console.log("Mail reader checks passed: safe HTML/styles/links, blocked trackers, raster CID signatures, opaque sandbox/CSP, HTML-only fallback, forwarded hierarchy, image-consent reset, portal switching/logout, and stale-response cleanup.");
})().catch(error=>{console.error(error);process.exitCode=1;});
