"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
const root=path.resolve(__dirname,".."),source=fs.readFileSync(path.join(root,"web/verification-code.js"),"utf8");
const descendants=node=>node.children.flatMap(child=>[child,...descendants(child)]);
class Element {
  constructor(tag="div"){this.tagName=tag.toUpperCase();this.children=[];this.dataset={};this.attributes={};this.events=new Map();this.value="";this.hidden=false;this.disabled=false;this.text="";const classes=new Set();this.classList={toggle(name,value){if(value===undefined)value=!classes.has(name);if(value)classes.add(name);else classes.delete(name);},add:name=>classes.add(name),remove:name=>classes.delete(name),contains:name=>classes.has(name)};}
  append(...nodes){this.children.push(...nodes);for(const node of nodes)node.parentElement=this;}
  replaceChildren(...nodes){this.children=[];this.append(...nodes);}
  set textContent(value){this.text=String(value);this.children=[];}
  get textContent(){return this.text+this.children.map(child=>child.textContent).join("");}
  setAttribute(name,value){this.attributes[name]=String(value);}
  removeAttribute(name){delete this.attributes[name];}
  getAttribute(name){return this.attributes[name]??null;}
  addEventListener(name,callback){this.events.set(name,callback);}
  fire(name,options={}){return this.events.get(name)?.({currentTarget:this,preventDefault(){},...options});}
  focus(){this.focused=true;if(this.ownerDocument)this.ownerDocument.activeElement=this;}
  select(){this.selected=true;}
  reset(){}
  close(){}
  querySelector(){return new Element("button");}
  querySelectorAll(selector){return selector==="button"?descendants(this).filter(node=>node.tagName==="BUTTON"):[];}
  contains(node){return node===this||descendants(this).includes(node);}
}
function fixture(){
  const requests=[],timers=new Map();let time=1700000000000,timerId=0,language="en";
  class Clock extends Date {static now(){return time;}}
  const translations={"Latest verification code":"最新验证码","Copy code":"复制验证码","Verification code":"验证码","No recent verification code.":"暂无近期验证码。","Verification code copied.":"验证码已复制。"};
  const sandbox={window:{},navigator:{},Date:Clock,document:{createElement:tag=>new Element(tag)},setTimeout(callback){const id=++timerId;timers.set(id,callback);return id;},clearTimeout:id=>timers.delete(id),PostPlusI18n:{get language(){return language;},t:(key,args={})=>{let value=language==="zh-CN"?translations[key]||key:key;for(const [name,replacement]of Object.entries(args))value=value.replaceAll("{"+name+"}",String(replacement));return value;}}};
  vm.runInNewContext(source,sandbox,{filename:"verification-code.js"});
  const element=new Element(),api=sandbox.window.PostPlusVerificationCode,component=api.create(element,{request:(url,options)=>new Promise((resolve,reject)=>requests.push({url,options,resolve,reject})),prefix:"test-code"});
  return {sandbox,element,component,requests,timers,id:name=>descendants(element).find(node=>node.id===`test-code-${name}`),record(changes={}){return {ok:true,found:true,code:"001234",message_id:"message-123",from:"Security <security@example.com>",subject:"Your verification code",received_at:time/1000-30,expires_at:time/1000+120,...changes};},advance(milliseconds){time+=milliseconds;},language(value){language=value;component.translate();}};
}
async function componentChecks(){
  const f=fixture();assert.equal(f.element.hidden,true);
  let pending=f.component.load();assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,"/api/verification-code?folder=INBOX");assert.equal(f.requests[0].options.quiet,true);
  f.requests[0].resolve(f.record({subject:"<script>literal subject</script>",from:"<img src=tracker>"}));await pending;
  assert.equal(f.id("value").value,"001234");assert.equal(f.id("copy").disabled,false);assert.match(f.element.textContent,/<script>literal subject<\/script>/);assert.match(f.element.textContent,/<img src=tracker>/);assert.equal(f.timers.size,1);
  await f.id("copy").fire("click");assert.equal(f.id("value").selected,true);assert.equal(f.id("value").focused,true);assert.match(f.element.textContent,/Code selected/);
  let copied="";f.sandbox.navigator.clipboard={writeText:async value=>{copied=value;}};
  const count=f.requests.length;await f.id("copy").fire("click");assert.equal(copied,"001234");assert.equal(f.requests.length,count,"Copy never reads or marks the source message");assert.match(f.element.textContent,/Verification code copied/);
  f.language("zh-CN");assert.equal(f.id("copy").textContent,"复制验证码");assert.match(f.element.textContent,/最新验证码|验证码已复制/);
  const first=f.component.load(),firstRequest=f.requests.at(-1),second=f.component.load(),secondRequest=f.requests.at(-1);
  secondRequest.resolve(f.record({code:"998877"}));await second;firstRequest.resolve(f.record({code:"111111"}));await first;assert.equal(f.id("value").value,"998877","Older request cannot replace the newest code");
  let finishCopy;f.sandbox.navigator.clipboard={writeText:()=>new Promise(resolve=>{finishCopy=resolve;})};
  const copy=f.id("copy").fire("click");pending=f.component.load();f.requests.at(-1).resolve(f.record({code:"765432"}));await pending;finishCopy();await copy;assert.equal(f.id("value").value,"765432");assert.doesNotMatch(f.element.textContent,/验证码已复制/);
  f.advance(121000);const expire=[...f.timers.values()][0];f.timers.clear();expire();assert.equal(f.id("value").value,"");assert.equal(f.id("copy").hidden,true);assert.equal(f.id("copy").disabled,true);
  for(const changes of [{expires_at:1},{code:"<script>123456</script>"},{code:"123456789012"},{found:false},{received_at:"yesterday"}]){pending=f.component.load();f.requests.at(-1).resolve(f.record(changes));await pending;assert.equal(f.id("copy").hidden,true);assert.equal(f.id("value").value,"");}
  pending=f.component.load();f.requests.at(-1).reject(new Error("<b>connection error</b>"));await pending;assert.match(f.element.textContent,/<b>connection error<\/b>/);assert.equal(f.id("copy").hidden,true);
  pending=f.component.load();const stale=f.requests.at(-1);f.component.reset();stale.resolve(f.record());await pending;assert.equal(f.element.hidden,true);assert.equal(f.id("value").value,"");assert.equal(f.timers.size,0);
  pending=f.component.load("Trash");assert.equal(f.requests.at(-1).url,"/api/verification-code?folder=Trash");f.requests.at(-1).resolve(f.record({code:"543210"}));await pending;assert.match(f.element.textContent,/Trash/);
  const oldFolder=f.component.load("INBOX"),oldRequest=f.requests.at(-1);pending=f.component.load("Trash");f.requests.at(-1).resolve(f.record({code:"876543"}));await pending;oldRequest.resolve(f.record({code:"123456"}));await oldFolder;assert.equal(f.id("value").value,"876543");
  const requestsBefore=f.requests.length;await f.component.load("Sent");assert.equal(f.element.hidden,true);assert.equal(f.requests.length,requestsBefore,"Unsupported folders reset without requests");
  pending=f.component.load();const disposed=f.requests.at(-1);f.component.dispose();disposed.resolve(f.record());await pending;assert.equal(f.element.children.length,0);assert.equal(f.timers.size,0);
  assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|\/api\/messages/);
}
async function badgeChecks(){
  const controls=new Map(),callbacks=new Map();let loads=0,resets=0;const folders=[];
  function create(tag="div"){const element=new Element(tag);element.ownerDocument=document;return element;}
  const document={getElementById(id){if(!controls.has(id))controls.set(id,create());return controls.get(id);},createElement:create,createElementNS:(ns,tag)=>create(tag),createDocumentFragment:()=>create("fragment"),querySelector:()=>new Element(),querySelectorAll:()=>[],addEventListener:(name,callback)=>callbacks.set(name,callback)};
  const sandbox={document,window:{},navigator:{},fetch:()=>new Promise(()=>{}),setTimeout:()=>1,clearTimeout(){},PostPlusI18n:{language:"en",t:(key,args={})=>{for(const [name,value]of Object.entries(args))key=key.replaceAll("{"+name+"}",String(value));return key;},error:value=>value.error||"error"},PostPlusAddress:{create:()=>({setDomain(){},address(){return "you@example.com";}})},PostPlusSize:{format:value=>String(value)},PostPlusMailReader:{create:()=>({clear(){},show(){}})},PostPlusVerificationCode:{create:()=>({load(folder){loads++;folders.push(folder);return Promise.resolve();},reset(){resets++;},translate(){}})},PostPlusPreferences:{closeNavigation(){}}};
  vm.createContext(sandbox);vm.runInContext(fs.readFileSync(path.join(root,"web/app.js"),"utf8"),sandbox,{filename:"app.js"});
  vm.runInContext('state.folders=[{name:"INBOX",total:50,unread:4,unseen:99},{name:"Sent",total:23,unread:9},{name:"Drafts",total:6,unread:0},{name:"Trash",total:31,unread:8},{name:"Junk",total:17,unread:3},{name:"Archive",total:100,unread:2}];renderFolderState();',sandbox);
  for(const [folder,value]of Object.entries({inbox:4,sent:0,drafts:6,trash:0,junk:3,archive:2})){assert.equal(controls.get("count-"+folder).textContent,String(value));assert.equal(controls.get("count-"+folder).hidden,value===0);}
  vm.runInContext('state.folders=[{name:"INBOX",total:50,unseen:17},{name:"Drafts",total:0},{name:"Junk",unread:-1},{name:"Archive",unread:"4"}];renderFolderState();',sandbox);
  for(const folder of ["inbox","drafts","junk","archive"])assert.equal(controls.get("count-"+folder).hidden,true,"Only valid unread/total fields supply badges");
  vm.runInContext('state.user={username:"you@example.com",csrf:"csrf"};api=async path=>path==="/api/folders"?{folders:[{name:"INBOX",total:40,unread:5}]}:{messages:[]};',sandbox);
  await vm.runInContext('loadInbox()',sandbox);assert.equal(loads,1,"Mail refresh loads the latest code independently");assert.equal(controls.get("count-inbox").textContent,"5");
  assert.equal(folders.at(-1),"INBOX");
  for(const view of ["Sent","Drafts","Junk","Archive"]){await vm.runInContext(`switchView("${view}")`,sandbox);assert.equal(loads,1,"Non-code folders never query recent codes");}
  await vm.runInContext('switchView("Trash")',sandbox);assert.equal(loads,2);assert.equal(folders.at(-1),"Trash");
  const beforeReset=resets;vm.runInContext('signedOut()',sandbox);assert.equal(resets,beforeReset+1,"Logout clears cached code and pending replies");
  vm.runInContext('state.user={username:"you@example.com",csrf:"csrf"};state.view="INBOX";state.selected="one";renderFolderState();',sandbox);
  const trigger=controls.get("message-move"),menu=controls.get("message-move-menu"),items=menu.querySelectorAll("button");
  assert.deepEqual(items.map(item=>item.dataset.moveFolder),["Sent","Drafts","Trash","Junk","Archive"]);assert.ok(items.every(item=>item.children[0].attributes["aria-hidden"]==="true"),"Every folder has a decorative SVG icon");
  trigger.fire("click");assert.equal(menu.hidden,false);assert.equal(trigger.attributes["aria-expanded"],"true");assert.equal(document.activeElement,items[0]);
  menu.fire("keydown",{key:"ArrowDown"});assert.equal(document.activeElement,items[1]);menu.fire("keydown",{key:"End"});assert.equal(document.activeElement,items.at(-1));menu.fire("keydown",{key:"Home"});assert.equal(document.activeElement,items[0]);
  menu.fire("keydown",{key:"Escape"});assert.equal(menu.hidden,true);assert.equal(document.activeElement,trigger);trigger.fire("keydown",{key:"ArrowUp"});assert.equal(document.activeElement,items.at(-1));
  menu.fire("keydown",{key:"Tab"});assert.equal(menu.hidden,true);assert.equal(document.activeElement,trigger,"Tab closes and restores focus before normal focus traversal");trigger.fire("click");callbacks.get("click")({target:new Element()});assert.equal(menu.hidden,true,"Click outside dismisses the folder menu");
  const moves=[];sandbox.captureMove=(path,options)=>moves.push({path,options});vm.runInContext('api=async(path,options)=>{captureMove(path,options);return path==="/api/folders"?{folders:[]}:{messages:[]};};',sandbox);
  await items[2].fire("click");assert.equal(moves[0].path,"/api/messages/one/move");assert.equal(moves[0].options.body.folder,"Trash");assert.equal(menu.hidden,true);
  vm.runInContext('state.folders=[{name:"Projects/客户",selectable:true,total:3,unread:2},{name:"<b>literal</b>",selectable:true,unread:1},{name:"Parent",selectable:false}];state.view="Projects/客户";renderFolderState();',sandbox);
  const custom=controls.get("custom-folders").querySelectorAll("button");
  assert.deepEqual(custom.map(item=>item.dataset.folder),["Projects/客户","<b>literal</b>"],"Custom IMAP folders are available in Webmail; namespace-only parents are excluded");
  assert.equal(controls.get("folder-title").textContent,"Projects/客户");assert.equal(custom[0].attributes["aria-current"],"page");
  assert.equal(custom[0].children.at(-1).textContent,"2");assert.match(custom[1].textContent,/<b>literal<\/b>/,"Folder names are literal text");
  assert.ok(menu.querySelectorAll("button").some(item=>item.dataset.moveFolder==="<b>literal</b>"),"Move menu includes client-created folders");
  vm.runInContext('signedOut()',sandbox);assert.equal(controls.get("custom-folders").children.length,0,"Logout clears private folder names");
  const html=fs.readFileSync(path.join(root,"web/index.html"),"utf8");assert.equal(html.split('src="/verification-code.js"').length-1,1);assert.equal(html.split('id="verification-code"').length-1,1);assert.ok(html.indexOf('src="/verification-code.js"')<html.indexOf('src="/app.js"'));
}
(async()=>{await componentChecks();await badgeChecks();console.log("Verification code UI checks passed: copy without Seen, expiry, safe source text, stale/logout replies, localization and folder badge semantics.");})().catch(error=>{console.error(error);process.exitCode=1;});
