"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
const script=fs.readFileSync(path.join(__dirname,"../web/admin-abuseipdb.js"),"utf8");
class Element{
  constructor(tag="div"){this.tagName=tag.toUpperCase();this.children=[];this.events={};this.attributes={};this.value="";this.text="";this.hidden=false;this.disabled=false;}
  append(...items){for(const item of items){if(item.parentElement)item.parentElement.children=item.parentElement.children.filter(child=>child!==item);item.parentElement=this;this.children.push(item);}}
  replaceChildren(...items){this.children.forEach(item=>item.parentElement=null);this.children=[];this.text="";this.append(...items);}
  set textContent(value){this.text=String(value);this.children=[];}
  get textContent(){return this.text+this.children.map(item=>item.textContent).join("");}
  setAttribute(key,value){this.attributes[key]=String(value);}
  addEventListener(name,callback){(this.events[name]??=[]).push(callback);}
  fire(name){return Promise.all((this.events[name]||[]).map(callback=>callback({preventDefault(){}})));}
  reportValidity(){return true;}
}
const nodes=root=>[root,...root.children.flatMap(nodes)];
const defaults={enabled:true,api_key_env:"POSTPLUS_ABUSEIPDB_API_KEY",verification_token:"",auto_ban:false,score_threshold:90,min_reports:3,ban_seconds:900,max_age_days:30,cache_seconds:3600,auto_report:false,report_threshold:20,report_categories:[18],report_cooldown_seconds:900};
const data=(revision=1)=>({ok:true,revision,settings:{...defaults},api_key_configured:true,quotas:[{endpoint:"bulk-check",supported:false}]});
function fixture(){const root=new Element(),requests=[],sandbox={window:{},document:{createElement:tag=>new Element(tag)},Date,PostPlusI18n:{language:"en",t:(key,args={})=>key.replace(/\{(\w+)\}/g,(all,name)=>args[name]??all)}};vm.runInNewContext(script,sandbox);const control=sandbox.window.PostPlusAdminAbuseIPDB.mount(root,{api:(url,options)=>new Promise((resolve,reject)=>requests.push({url,options,resolve,reject}))});return {root,requests,control,id:id=>nodes(root).find(item=>item.id==="abuse-"+id),button:text=>nodes(root).find(item=>item.tagName==="BUTTON"&&item.textContent===text),forms:()=>nodes(root).filter(item=>item.tagName==="FORM")};}
async function run(){
  const f=fixture();assert.equal(f.requests.length,0);assert.equal(f.button("Run AbuseIPDB request").disabled,true);
  let pending=f.control.refresh();f.requests.at(-1).resolve(data());await pending;
  assert.match(f.root.textContent,/Uses check capacity/);assert.match(f.root.textContent,/Unknown/);assert.equal(f.id("api-key").value,"");assert.equal(f.id("score_threshold").value,"90");
  assert.equal(f.id("report_threshold").min,"2","The browser enforces the backend's minimum local failure threshold");
  f.id("endpoint").value="blacklist";await f.id("endpoint").fire("change");assert.equal(f.id("tool-limit").max,"10000","The blacklist form matches the server's bounded result limit");
  f.id("endpoint").value="reports";await f.id("endpoint").fire("change");assert.equal(f.id("tool-page").max,"1000000");
  f.id("tool-ipAddress").value="8.8.8.8";pending=f.forms()[1].fire("submit");f.requests.at(-1).resolve({ok:true,data:[],meta:{lastPage:3}});await pending;assert.match(f.root.textContent,/lastPage/,"Pagination metadata must remain inspectable");
  const detached=f.id("tool-ipAddress");detached.disabled="detached";
  f.id("endpoint").value="check";await f.id("endpoint").fire("change");assert.equal(detached.disabled,"detached","Endpoint changes release detached form controls from future updates");
  f.id("api-key").value="new-test-secret";f.id("verification-token").value="abuseipdb-verification-example";pending=f.forms()[0].fire("submit");let request=f.requests.at(-1);assert.equal(request.url,"/api/admin/abuseipdb/settings");assert.equal(request.options.body.revision,1);assert.equal(request.options.body.settings.api_key,"new-test-secret");assert.deepEqual(Array.from(request.options.body.settings.report_categories),[18]);request.resolve(data(2));await pending;assert.equal(f.id("api-key").value,"");
  pending=f.forms()[0].fire("submit");request=f.requests.at(-1);assert.equal(Object.hasOwn(request.options.body.settings,"api_key"),false,"Blank keeps the existing secret");request.resolve(data(3));await pending;
  f.id("tool-ipAddress").value="8.8.8.8";pending=f.forms()[1].fire("submit");request=f.requests.at(-1);assert.equal(request.url,"/api/admin/abuseipdb/check");assert.equal(request.options.body.ipAddress,"8.8.8.8");request.resolve({ok:true,data:{abuseConfidenceScore:95,totalReports:17,comment:"<img src=x onerror=alert(1)>"},quotas:[{endpoint:"check",limit:1000,used:12,remaining:988,reset_at:1792890000}]});await pending;assert.match(f.root.textContent,/12 \/ 1,000/);assert.match(f.root.textContent,/1.2%/);assert.match(f.root.textContent,/Abuse confidence: 95%/);assert.match(f.root.textContent,/<img src=x onerror=alert\(1\)>/);
  f.id("endpoint").value="bulk-check";await f.id("endpoint").fire("change");f.id("tool-ips").value="8.8.8.8\n1.1.1.1";pending=f.forms()[1].fire("submit");request=f.requests.at(-1);assert.deepEqual(Array.from(request.options.body.ips),["8.8.8.8","1.1.1.1"]);request.resolve({ok:true,data:[]});await pending;
  f.id("endpoint").value="bulk-report";await f.id("endpoint").fire("change");f.id("tool-reports").value='IP,Categories,ReportDate,Comment\r\n8.8.8.8,"18,21",2026-10-25T12:00:00Z,"line one\nline two, with ""quotes"""';pending=f.forms()[1].fire("submit");request=f.requests.at(-1);assert.equal(request.options.body.reports.length,1);assert.deepEqual(Array.from(request.options.body.reports[0].categories),[18,21]);assert.equal(request.options.body.reports[0].comment,'line one\nline two, with "quotes"');assert.equal(request.options.body.reports[0].timestamp,"2026-10-25T12:00:00Z");request.resolve({ok:true,data:{savedReports:1}});await pending;
  f.id("tool-reports").value='IP,Categories,Comment\n8.8.8.8,18,"unclosed';const before=f.requests.length;await f.forms()[1].fire("submit");assert.equal(f.requests.length,before);assert.match(f.root.textContent,/unclosed quoted field/);
  f.id("tool-reports").value='IP,Categories,Comment\n8.8.8.8,18,unescaped"quote';await f.forms()[1].fire("submit");assert.equal(f.requests.length,before,"Malformed unquoted fields are rejected before consuming report capacity");assert.match(f.root.textContent,/columns and quoting/);
  f.id("tool-reports").value='IP,Categories,Comment,Comment\n8.8.8.8,18,first,second';await f.forms()[1].fire("submit");assert.equal(f.requests.length,before,"Duplicate CSV headers cannot silently discard evidence columns");
  f.id("endpoint").value="clear-address";await f.id("endpoint").fire("change");assert.match(f.root.textContent,/Remove your own reports/);f.id("tool-ipAddress").value="8.8.8.8";pending=f.forms()[1].fire("submit");request=f.requests.at(-1);assert.equal(request.url,"/api/admin/abuseipdb/clear-address");request.reject(Object.assign(new Error("Quota exceeded"),{data:{quotas:[{endpoint:"clear-address",limit:5,used:5,remaining:0}]}}));await pending;assert.match(f.root.textContent,/5 \/ 5/);assert.match(f.root.textContent,/Quota exceeded/);
  pending=f.control.refresh();request=f.requests.at(-1);f.control.dispose();request.resolve(data());await pending;assert.equal(f.root.children.length,0,"Late replies cannot restore secret/admin state after sign-out");
  assert.doesNotMatch(script,/innerHTML|localStorage|sessionStorage/);
  console.log("AbuseIPDB UI checks passed: real quotas, secret handling, endpoint forms, CSV quoting, failures and logout isolation.");
}
run().catch(error=>{console.error(error);process.exitCode=1;});
