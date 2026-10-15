"use strict";
// Administrator key workflow and secret lifetime, without network or browser storage.
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const vm=require("node:vm");
const source=fs.readFileSync(path.join(__dirname,"../web/admin.js"),"utf8");
const html=fs.readFileSync(path.join(__dirname,"../web/admin.html"),"utf8");
const secret="pp_"+"a".repeat(64),keyId="b".repeat(32);
const key={id:keyId,name:"<img src=x>",prefix:"pp_aaaaaaaa",owner:"admin@example.com",scope:"admin",created_at:Math.floor(Date.now()/1000),expires_at:null,last_used_at:null,revoked_at:null,active:true};
const list=()=>({ok:true,api_keys:[{...key}],max_active_keys:100,max_stored_keys:1000});
function fixture() {
  const controls=new Map(),calls=[],events=new Map(),clipboard=[],timers=new Map();let timerId=0;
  class Control {
    constructor(tag="div"){this.tagName=tag;this.children=[];this.dataset={};this.value="";this.textContent="";this.hidden=false;this.attributes={};this.callbacks={};this.classList={toggle(){},add(){},remove(){}};}
    append(...children){this.children.push(...children);}
    replaceChildren(...children){this.children=[];this.append(...children);}
    setAttribute(name,value){this.attributes[name]=String(value);}
    removeAttribute(name){delete this.attributes[name];}
    addEventListener(name,callback){this.callbacks[name]=callback;}
    querySelector(){return id(this.id==="api-key-form"?"api-key-create-submit":this.id==="api-key-revoke-form"?"revoke-submit":this.id+"-submit");}
    querySelectorAll(){return [];}
    reset(){if(this.id==="api-key-form"){id("api-key-name").value="";id("api-key-expiry").value="";}}
    focus(){this.focused=true;}
    select(){this.selected=true;}
    showModal(){this.open=true;}
    close(){this.open=false;this.fire("close");}
    fire(name){return this.callbacks[name]?.({preventDefault(){},currentTarget:this,target:this});}
  }
  function id(name){if(!controls.has(name)){const node=new Control();node.id=name;controls.set(name,node);}return controls.get(name);}
  const close=new Control("button");close.dataset.close="api-key-dialog";
  const sandbox={window:{},document:{getElementById:id,createElement:tag=>new Control(tag),createDocumentFragment:()=>new Control("fragment"),title:"",
    querySelectorAll:selector=>selector==="[data-close]"?[close]:selector==="dialog[open]"?[...controls.values()].filter(node=>node.open):[],
    addEventListener(name,callback){events.set(name,callback);}},
    PostPlusI18n:{language:"en",t:(text,args={})=>text.replace(/\{(\w+)\}/g,(match,name)=>args[name]??match),error:data=>data.error||"Failed"},
    PostPlusAddress:{create:()=>({setDomain(){},setAddress(){},address:()=>"admin@example.com"})},
    PostPlusPreferences:{closeNavigation(){}},PostPlusSize:{format:()=>"0 B"},PostPlusMailReader:{bodySource:raw=>raw||"",create:()=>({show(){},clear(){}})},URL,TextEncoder,AbortController,
    location:{origin:"http://localhost:8081"},navigator:{clipboard:{writeText:async value=>clipboard.push(value)}},
    localStorage:{getItem(){throw new Error("Keys must not use browser storage");},setItem(){throw new Error("Keys must not use browser storage");}},
    setTimeout:callback=>{const id=++timerId;timers.set(id,callback);return id;},clearTimeout:id=>timers.delete(id),fetch:async route=>({ok:route==="/api/public/config",status:route==="/api/public/config"?200:401,json:async()=>route==="/api/public/config"?{ok:true,domain:"example.com"}:{ok:false}})};
  vm.createContext(sandbox);vm.runInContext(source,sandbox,{filename:"admin.js"});
  return {sandbox,id,controls,calls,events,clipboard,timers,close,run:code=>vm.runInContext(code,sandbox),
    async tick(){const [id,callback]=timers.entries().next().value || [];if(callback){timers.delete(id);await callback();}},
    async ready(){for(let i=0;i<12;i++)await Promise.resolve();this.run('state.user={username:"admin@example.com",admin:true,csrf:"test-csrf"};');},
    respond(handler){sandbox.fetch=async(route,options)=>{calls.push({route,options});return {ok:true,status:200,json:async()=>handler(route,options)};};}};
}
async function run() {
  for(const identifier of ["nav-api-keys","view-api-keys","api-key-dialog","api-key-secret","api-key-revoke-dialog"])assert.match(html,new RegExp(`id="${identifier}"`));
  assert.match(html,/<textarea[^>]*id="api-key-secret"[^>]*readonly/);
  const f=fixture();await f.ready();f.respond(route=>route==="/api/admin/api-keys"?list():{ok:true});
  await f.run("loadApiKeys()");
  assert.equal(f.calls[0].options.headers["X-CSRF-Token"],"test-csrf","Browser metadata GET retains its session CSRF header");
  assert.equal(f.calls[0].options.credentials,"same-origin");assert.equal(f.calls[0].options.cache,"no-store");
  assert.equal(Object.hasOwn(f.calls[0].options,"signal"),false,"Ordinary API calls retain their existing request behavior");
  const row=f.id("api-keys-body").children[0].children[0];
  assert.equal(row.children[0].children[0].textContent,key.name,"Untrusted names render as text");
  assert.equal(row.children[4].textContent,"Never expires");assert.equal(row.children[5].textContent,"Never used");
  assert.equal(f.run('apiKeyStatus({active:false,revoked_at:1,expires_at:0})'),"Revoked");
  assert.equal(f.run('apiKeyStatus({active:false,revoked_at:null,expires_at:1})'),"Expired");
  let createdResponse;f.respond((route,options)=>options.method==="POST"?(createdResponse={ok:true,key:secret,api_key:{...key}}):list());
  await f.id("api-key-create-open").fire("click");f.id("api-key-name").value="Monitoring";f.id("api-key-expiry").value="90";
  await f.id("api-key-form").fire("submit");
  const create=f.calls.find(call=>call.options.method==="POST");
  assert.deepEqual(JSON.parse(create.options.body),{name:"Monitoring",expires_in_days:90});
  assert.equal(create.options.headers["X-CSRF-Token"],"test-csrf");
  assert.equal(f.id("api-key-secret").value,secret);assert.equal(f.id("api-key-secret").selected,true);
  assert.equal(createdResponse.key,"","Creation response does not retain another secret copy");
  assert.equal(f.id("api-key-created").hidden,false);assert.equal(f.id("api-key-create-submit").hidden,true);
  await f.id("api-key-copy").fire("click");assert.deepEqual(f.clipboard,[secret]);
  await f.close.fire("click");assert.equal(f.id("api-key-secret").value,"");assert.equal(f.id("api-key-created").hidden,true);
  await f.id("api-key-create-open").fire("click");f.id("api-key-name").value="监".repeat(27);f.calls.length=0;
  await f.id("api-key-form").fire("submit");assert.equal(f.calls.length,0,"80-byte limit uses UTF-8 bytes");
  f.id("api-key-name").value="Monitoring";f.id("api-key-expiry").value="1.5";
  await f.id("api-key-form").fire("submit");assert.equal(f.calls.length,0,"Fractional expiry is rejected");
  f.id("api-key-expiry").value="";f.id("api-key-expiry").validity={badInput:true};
  await f.id("api-key-form").fire("submit");assert.equal(f.calls.length,0,"An incomplete number cannot become an unlimited key");
  f.id("api-key-expiry").validity={badInput:false};
  f.id("api-key-expiry").value="";await f.id("api-key-form").fire("submit");
  assert.deepEqual(JSON.parse(f.calls[0].options.body),{name:"Monitoring"},"No expiry is omitted");
  f.respond(route=>route==="/api/admin/api-keys"?list():{ok:true});
  await f.id("logout").fire("click");assert.equal(f.id("api-key-secret").value,"");
  assert.equal(f.id("api-keys-body").children.length,0,"Logout clears key metadata");
  const revoked=fixture();await revoked.ready();revoked.respond((route,options)=>options.method==="DELETE"?{ok:true,api_key:{...key,active:false,revoked_at:1}}:list());
  revoked.run('openApiKeyRevoke({id:"'+keyId+'",name:"Monitoring"})');await revoked.id("api-key-revoke-form").fire("submit");
  assert.equal(revoked.calls[0].route,"/api/admin/api-keys/"+keyId);assert.equal(revoked.calls[0].options.method,"DELETE");assert.equal(revoked.calls[0].options.headers["X-CSRF-Token"],"test-csrf");
  assert.equal(revoked.id("api-key-revoke-dialog").open,false);
  const stale=fixture();await stale.ready();let finish;
  stale.sandbox.fetch=async(route,options)=>({ok:true,status:200,json:()=>options.method==="POST"?new Promise(resolve=>{finish=resolve;}):list()});
  stale.id("api-key-create-open").fire("click");stale.id("api-key-name").value="Late key";
  const pending=stale.id("api-key-form").fire("submit");for(let i=0;i<5;i++)await Promise.resolve();
  stale.id("api-key-dialog").close();finish({ok:true,key:secret,api_key:{...key}});await pending;
  assert.equal(stale.id("api-key-secret").value,"","A late response cannot restore a closed dialog's secret");
  const logout=fixture();await logout.ready();let finishLogout;
  logout.sandbox.fetch=async(route,options)=>({ok:true,status:200,json:()=>options.method==="POST"?new Promise(resolve=>{finishLogout=resolve;}):list()});
  logout.id("api-key-create-open").fire("click");logout.id("api-key-name").value="Late key";
  const late=logout.id("api-key-form").fire("submit");for(let i=0;i<5;i++)await Promise.resolve();
  logout.run("signedOut()");finishLogout({ok:true,key:secret,api_key:{...key}});await late;
  assert.equal(logout.id("api-key-secret").value,"","Logout rejects a stale creation response");
  const copy=fixture();await copy.ready();let copied;
  copy.id("api-key-dialog").showModal();copy.id("api-key-secret").value=secret;
  copy.sandbox.navigator.clipboard.writeText=()=>new Promise(resolve=>{copied=resolve;});const copying=copy.id("api-key-copy").fire("click");
  copy.id("api-key-dialog").close();copied();await copying;assert.equal(copy.id("api-key-copy-status").textContent,"","Late clipboard success does not restore dialog state");
  copy.sandbox.navigator.clipboard={};copy.id("api-key-dialog").showModal();copy.id("api-key-secret").value=secret;
  await copy.id("api-key-copy").fire("click");assert.match(copy.id("api-key-copy-status").textContent,/manually/);
  console.log("API key UI checks passed: protected metadata, validation, one-time secret/copy, revoke, logout, and stale-response cleanup.");
}
module.exports={fixture};
if(require.main===module)run().catch(error=>{console.error(error);process.exitCode=1;});
