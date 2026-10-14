"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),vm=require("node:vm"),path=require("node:path");
const source=fs.readFileSync(path.join(__dirname,"../web/admin.js"),"utf8");
const controls=new Map(),calls=[];
function control(){return {value:"",hidden:false,disabled:false,children:[],listeners:{},textContent:"",append(...nodes){this.children.push(...nodes);},replaceChildren(...nodes){this.children=nodes;},setAttribute(){},removeAttribute(){},addEventListener(name,callback){this.listeners[name]=callback;}};}
const id=name=>{if(!controls.has(name))controls.set(name,control());return controls.get(name);};
const sandbox={$:id,state:{user:{admin:true}},URLSearchParams,setTimeout,clearTimeout,t:(text,args={})=>text.replace("{count}",args.count),
  document:{createDocumentFragment:control},element:()=>control(),formError:(name,message)=>{id(name).textContent=message;},
  api:(route)=>new Promise((resolve,reject)=>calls.push({route,resolve,reject}))};
vm.createContext(sandbox);vm.runInContext(source.slice(source.indexOf("let logVersion ="),source.indexOf("function setLink(")),sandbox);
const result=(message,cursor="next")=>({entries:[{timestamp:"2026-10-14",service:"smtp",level:"info",pid:12,message}],services:["smtp"],next_cursor:cursor});
(async()=>{
  id("logs-search").value="验证 & code";
  let loading=sandbox.loadLogs();
  assert.equal(new URLSearchParams(calls[0].route.split("?")[1]).get("q"),"验证 & code");
  calls[0].resolve(result("first","opaque+/="));await loading;
  assert.equal(id("logs-more").hidden,false);
  loading=sandbox.loadLogs(true);
  assert.equal(new URLSearchParams(calls[1].route.split("?")[1]).get("cursor"),"opaque+/=");
  calls[1].reject(new Error("temporary failure"));await loading;
  assert.equal(id("logs-more").disabled,false);
  assert.equal(vm.runInContext("logData.entries.length",sandbox),1,"Failed page keeps prior rows and permits retry");
  loading=sandbox.loadLogs(true);calls[2].resolve(result("second",""));await loading;
  assert.equal(vm.runInContext("logData.entries.length",sandbox),2);assert.equal(id("logs-more").hidden,true);
  let previous=sandbox.loadLogs();
  id("logs-search").value="new filter";loading=sandbox.loadLogs();
  calls[4].resolve(result("new search",""));await loading;
  calls[3].resolve(result("stale"));await previous;
  assert.equal(vm.runInContext("logData.entries[0].message",sandbox),"new search","Stale reply must not replace new search");
  console.log("Log UI checks passed: encoded search, paging, retry, exhaustion and stale replies.");
})().catch(error=>{console.error(error);process.exitCode=1;});
