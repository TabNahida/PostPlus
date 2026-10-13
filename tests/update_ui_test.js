"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
const root=path.resolve(__dirname,"..");
const descendants=element=>element.children.flatMap(child=>[child,...descendants(child)]);
class Element {
  constructor(tag="div"){this.tagName=tag.toUpperCase();this.children=[];this.events=new Map();this.attributes={};this.hidden=false;this.disabled=false;this.textContent="";}
  get textContent(){return this.text+this.children.map(child=>child.textContent).join("");}
  set textContent(value){this.text=String(value);this.children=[];}
  append(...items){for(const item of items){item.parentElement=this;this.children.push(item);}}
  replaceChildren(...items){this.children=[];this.append(...items);}
  setAttribute(name,value){this.attributes[name]=value;}
  addEventListener(name,listener){if(!this.events.has(name))this.events.set(name,[]);this.events.get(name).push(listener);}
  async fire(name){for(const listener of this.events.get(name)||[])await listener({target:this});}
}
function fixture(){
  const element=new Element(),calls=[],activity=[],timers=new Map();let responder=()=>({ok:true,current_version:"0.2.1",state:"idle",available:true}),nextTimer=0,time=1000;
  const sandbox={window:{},URL,location:{href:"https://mail.example.com:8081/"},PostPlusI18n:{t:(key,parameters={})=>key.replace(/\{(\w+)\}/g,(m,k)=>parameters[k]??m)},document:{createElement:tag=>new Element(tag)},Date:class extends Date{static now(){return time;}},setTimeout(fn,delay){const id=++nextTimer;timers.set(id,{fn,delay});return id;},clearTimeout:id=>timers.delete(id)};
  vm.runInNewContext(fs.readFileSync(path.join(root,"web/update.js"),"utf8"),sandbox);
  let allowed=true;
  const component=sandbox.window.PostPlusUpdate.create(element,{prefix:"test",canChange:()=>allowed,onBusy:busy=>activity.push(busy),request:async(route,options={})=>{calls.push({route,options});return responder(route,options);}});
  return {component,element,calls,activity,timers,id:name=>descendants(element).find(item=>item.id===`test-${name}`),respond:fn=>{responder=fn;},allow:value=>{allowed=value;},advance:ms=>{time+=ms;},async tick(){const first=timers.entries().next().value;if(first){timers.delete(first[0]);await first[1].fn();}}};
}
const release={ok:true,version:"0.2.2",current_version:"0.2.1",update_available:true,files:[{path:"bin/postplus-smtp"},"web/app.js"],services:["smtp","web"],download_bytes:12345};
const job=state=>({ok:true,job_id:"update-test",version:"0.2.2",state,services:["smtp","web"],files:["bin/postplus-smtp","web/app.js"]});
async function prepared(){const f=fixture();await f.component.load();f.respond((route,options)=>route.endsWith("/check")?release:job("pending_download"));await f.id("check").fire("click");await f.id("stage").fire("click");f.respond(()=>job("staged"));await f.tick();return f;}
async function run(){
  const f=fixture();await f.component.load();assert.match(f.element.textContent,/Installed version: 0.2.1/);assert.equal(f.id("stage").hidden,true);
  f.respond(()=>release);await f.id("check").fire("click");assert.match(f.id("status").textContent,/Release 0.2.2 is available/);assert.match(f.element.textContent,/bin\/postplus-smtp/);assert.equal(f.id("stage").hidden,false);assert.equal(f.id("apply").hidden,true,"Checking cannot apply a release");
  f.respond(()=>job("pending_download"));await f.id("stage").fire("click");assert.deepEqual(JSON.parse(JSON.stringify(f.calls.at(-1).options.body)),{version:"0.2.2"});assert.equal(f.id("apply").hidden,true);assert.equal(f.id("check").disabled,true);
  f.respond(()=>job("downloading"));await f.tick();assert.equal(f.activity.at(-1),true);assert.match(f.id("status").textContent,/Downloading and verifying/);
  f.respond(()=>job("staged"));await f.tick();assert.equal(f.activity.at(-1),false);assert.equal(f.id("apply").hidden,false);assert.equal(f.timers.size,0,"Prepared download waits for an explicit apply click");
  f.respond(()=>({...job("pending_apply"),requires_launcher_restart:true}));await f.id("apply").fire("click");assert.deepEqual(JSON.parse(JSON.stringify(f.calls.at(-1).options.body)),{job_id:"update-test"});assert.match(f.id("status").textContent,/launcher will restart/);
  f.respond(()=>({...job("complete"),current_version:"0.2.2"}));await f.tick();assert.match(f.id("status").textContent,/Update 0.2.2 completed/);assert.equal(f.activity.at(-1),false);assert.equal(f.timers.size,0);assert.equal(f.id("stage").hidden,true,"A completed job must not offer its same update again");
  const failed=await prepared();failed.respond(()=>({...job("failed"),rolled_back:true,error:"Readiness failed"}));await failed.id("apply").fire("click");assert.match(failed.id("status").textContent,/Previous files and services were restored/);assert.match(failed.element.textContent,/Readiness failed/);
  const lost=await prepared();lost.respond(route=>{if(route.endsWith("/apply"))throw new Error("Connection interrupted");throw Object.assign(new Error("Expired"),{status:401});});await lost.id("apply").fire("click");assert.equal(lost.timers.size,1,"A lost apply reply checks the existing job rather than resubmitting");await lost.tick();assert.match(lost.id("status").textContent,/could not be confirmed/);assert.doesNotMatch(lost.id("status").textContent,/completed\./);assert.equal(lost.id("open").hidden,false);assert.equal(lost.activity.at(-1),false);assert.equal(lost.timers.size,0);assert.equal(lost.calls.filter(call=>call.route.endsWith("/apply")).length,1);
  const timeout=await prepared();timeout.respond(()=>job("pending_apply"));await timeout.id("apply").fire("click");timeout.respond(()=>{throw new Error("Offline");});timeout.advance(90001);await timeout.tick();assert.match(timeout.id("status").textContent,/could not be confirmed/);assert.equal(timeout.timers.size,0);
  const stale=fixture();let resolve;stale.respond(()=>new Promise(done=>{resolve=done;}));const loading=stale.component.load();stale.component.dispose();resolve({...job("downloading")});await loading;assert.equal(stale.element.children.length,0);assert.equal(stale.timers.size,0);
  const blocked=fixture();blocked.respond(()=>({...release,state:"idle"}));await blocked.component.load();blocked.allow(false);await blocked.id("stage").fire("click");assert.equal(blocked.calls.length,1,"Maintenance exclusion is checked before mutations");
  const unavailable=fixture();unavailable.respond(()=>({ok:true,available:false,state:"idle",current_version:"0.2.1"}));await unavailable.component.load();assert.equal(unavailable.id("check").disabled,true);assert.match(unavailable.id("status").textContent,/unavailable/);
  const upToDate=fixture();upToDate.respond(()=>({...release,version:"0.2.1",update_available:false}));await upToDate.id("check").fire("click");assert.match(upToDate.id("status").textContent,/up to date/);assert.equal(upToDate.id("stage").hidden,true);
  const unsupported=fixture();unsupported.respond(()=>({...release,supported:false,release_url:"https://github.com/TabNahida/PostPlus/releases/tag/v0.2.2"}));await unsupported.id("check").fire("click");assert.equal(unsupported.id("stage").hidden,true);assert.equal(unsupported.id("release").hidden,false);assert.match(unsupported.id("status").textContent,/manual upgrade/);
  const html=fs.readFileSync(path.join(root,"web/admin.html"),"utf8");assert.equal(html.split('src="/update.js"').length-1,1);
  console.log("Update UI checks passed: checked release, incremental plan, separate download/apply, progress, rollback, disconnect, bounded polling and stale-response cleanup.");
}
run().catch(error=>{console.error(error);process.exitCode=1;});
