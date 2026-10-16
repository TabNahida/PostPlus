"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
const script=fs.readFileSync(path.join(__dirname,"../web/admin-security.js"),"utf8");
class Element{
  constructor(tag="div"){this.tagName=tag.toUpperCase();this.children=[];this.events={};this.attributes={};this.value="";this.text="";this.hidden=false;this.disabled=false;}
  append(...items){this.children.push(...items);}
  prepend(...items){this.children.unshift(...items);}
  replaceChildren(...items){this.children=[];this.text="";this.append(...items);}
  set textContent(value){this.text=String(value);this.children=[];}
  get textContent(){return this.text+this.children.map(item=>item.textContent).join("");}
  setAttribute(key,value){this.attributes[key]=String(value);}
  addEventListener(name,callback){this.events[name]=callback;}
  fire(name){return this.events[name]?.({preventDefault(){}});}
  reportValidity(){return true;}
}
const nodes=root=>[root,...root.children.flatMap(nodes)];
const defaults={enabled:true,window_seconds:300,failure_threshold:20,unknown_user_threshold:5,ban_seconds:900,allowlist:[]};
function fixture(){
  const root=new Element(),requests=[],notices=[],sandbox={window:{},document:{createElement:tag=>new Element(tag)},Date,TextEncoder,PostPlusI18n:{language:"en",t:(key,args={})=>key.replace(/\{(\w+)\}/g,(all,name)=>args[name]??all)}};
  vm.runInNewContext(script,sandbox);
  const control=sandbox.window.PostPlusAdminSecurity.mount(root,{api:(url,options)=>new Promise((resolve,reject)=>requests.push({url,options,resolve,reject})),notice:message=>notices.push(message)});
  return {root,requests,notices,control,id:id=>nodes(root).find(item=>item.id===id),button:text=>nodes(root).find(item=>item.tagName==="BUTTON"&&item.textContent===text),forms:()=>nodes(root).filter(item=>item.tagName==="FORM")};
}
const result=(revision=1,bans=[])=>({policy:{...defaults,allowlist:[]},revision,bans,server_time:1700000000});
const tick=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
async function run(){
  const f=fixture();assert.equal(f.requests.length,0,"The admin panel loads only when opened");assert.equal(f.button("Save security policy").disabled,true);
  let pending=f.control.refresh();assert.equal(f.requests[0].url,"/api/admin/security");
  const unsafe="<img src=x onerror=alert(1)>";
  f.requests[0].resolve(result(1,[{ip:"192.0.2.4",reason:"unknown_account_attempts",expires_at:1700000900,failures:7,unknown_failures:5,automatic:true},{ip:"2001:db8::4",reason:unsafe,expires_at:1700000900,failures:0,unknown_failures:0,automatic:false}]));await pending;
  assert.equal(f.id("security-unknown-user-threshold").value,"5");assert.equal(f.id("security-failure-threshold").value,"20");assert.match(f.root.textContent,/Too many unknown-account attempts/);assert.match(f.root.textContent,/<img src=x onerror=alert\(1\)>/);assert.equal(f.button("Save security policy").disabled,true);
  f.id("security-ban-search").value="2001:db8";f.id("security-ban-search").fire("input");assert.match(f.root.textContent,/1 of 2 active IP blocks/);assert.doesNotMatch(f.root.textContent,/Too many unknown-account attempts/);
  f.id("security-ban-search").value="";f.id("security-ban-search").fire("input");
  const threshold=f.id("security-unknown-user-threshold");threshold.value="3";threshold.fire("input");f.id("security-allowlist").value=" 192.0.2.10 \n\n 2001:db8::/64 ";f.id("security-allowlist").fire("input");assert.equal(f.button("Save security policy").disabled,false);
  pending=f.forms()[0].fire("submit");const save=f.requests.at(-1);assert.equal(save.url,"/api/admin/security/policy");assert.equal(save.options.method,"PUT");assert.deepEqual(JSON.parse(JSON.stringify(save.options.body)),{policy:{...defaults,unknown_user_threshold:3,allowlist:["192.0.2.10","2001:db8::/64"]},revision:1});assert.equal(threshold.disabled,true);
  save.resolve({policy:save.options.body.policy,revision:2});await pending;assert.equal(f.button("Save security policy").disabled,true);assert.equal(threshold.disabled,false);assert.deepEqual(f.notices,["Security policy saved."]);
  pending=f.button("Unblock").fire("click");assert.equal(f.requests.at(-1).url,"/api/admin/security/unban");assert.equal(f.requests.at(-1).options.body.ip,"192.0.2.4");f.requests.at(-1).resolve({});await tick();assert.equal(f.requests.at(-1).url,"/api/admin/security");f.requests.at(-1).resolve({...result(2),policy:save.options.body.policy});await pending;assert.match(f.root.textContent,/No active IP blocks/);
  threshold.value="4";threshold.fire("input");pending=f.control.refresh();f.requests.at(-1).resolve(result(3));await pending;assert.equal(threshold.value,"4","Refreshing blocks preserves unsaved policy edits");assert.equal(f.button("Save security policy").disabled,true,"A conflicting policy revision requires explicit reload");assert.match(f.root.textContent,/changed elsewhere/);
  pending=f.button("Reload security policy").fire("click");f.requests.at(-1).resolve(result(3));await pending;assert.equal(threshold.value,"5");threshold.value="2";threshold.fire("input");pending=f.forms()[0].fire("submit");f.requests.at(-1).reject(Object.assign(new Error("Policy conflict"),{status:409}));await pending;assert.equal(f.button("Save security policy").disabled,true);assert.match(f.root.textContent,/Policy conflict/);assert.equal(threshold.value,"2");
  pending=f.button("Reload security policy").fire("click");f.requests.at(-1).resolve(result(4));await pending;
  f.id("security-manual-ip").value=" 192.0.2.9 ";f.id("security-manual-seconds").value="600";f.id("security-manual-reason").value=" Test ";pending=f.forms()[1].fire("submit");assert.deepEqual(JSON.parse(JSON.stringify(f.requests.at(-1).options)),{method:"POST",body:{ip:"192.0.2.9",seconds:600,reason:"Test"}});f.requests.at(-1).resolve({});await tick();f.requests.at(-1).resolve(result(4));await pending;assert.equal(f.id("security-manual-ip").value,"");assert.equal(f.id("security-manual-reason").value,"");
  const before=f.requests.length;f.id("security-manual-ip").value="192.0.2.9";f.id("security-manual-reason").value="封".repeat(54);await f.forms()[1].fire("submit");assert.equal(f.requests.length,before,"Manual reason limit counts UTF-8 bytes");assert.match(f.root.textContent,/160 UTF-8 bytes/);
  f.id("security-manual-reason").value="";pending=f.forms()[1].fire("submit");assert.equal(Object.hasOwn(f.requests.at(-1).options.body,"reason"),false,"Blank optional reason is omitted");f.requests.at(-1).resolve({});await tick();f.requests.at(-1).resolve(result(4));await pending;
  f.id("security-allowlist").value=Array.from({length:101},(_,i)=>`192.0.2.${i}`).join("\n");f.id("security-allowlist").fire("input");const beforePolicy=f.requests.length;await f.forms()[0].fire("submit");assert.equal(f.requests.length,beforePolicy,"The UI and backend share the 100-entry allowlist limit");assert.match(f.root.textContent,/up to 100 entries/);
  f.control.translate();assert.equal(f.id("security-unknown-user-threshold").value,"5","Language changes preserve policy values");
  pending=f.control.refresh();const stale=f.requests.at(-1);f.control.dispose();stale.resolve(result(4,[{ip:"private",reason:"private",expires_at:1700000900}]));await pending;assert.equal(f.root.children.length,0,"A response after logout cannot restore private security data");
  const failed=fixture();pending=failed.control.refresh();failed.requests[0].reject(new Error("Offline"));await pending;assert.match(failed.root.textContent,/Offline/);assert.equal(failed.button("Save security policy").disabled,true);pending=failed.control.refresh();failed.requests.at(-1).resolve(result());await pending;assert.equal(failed.id("security-enabled").disabled,false,"Failed initial load remains recoverable");
  assert.doesNotMatch(script,/innerHTML|localStorage|sessionStorage/);
  const html=fs.readFileSync(path.join(__dirname,"../web/admin.html"),"utf8");assert.match(html,/id="nav-security"/);assert.match(html,/src="\/admin-security.js"/);assert.match(html,/href="\/admin-security.css"/);
  console.log("Security UI checks passed: policy revision/validation state, stale edit protection, searchable safe ban rows, manual block/unblock and logout isolation.");
}
run().catch(error=>{console.error(error);process.exitCode=1;});
