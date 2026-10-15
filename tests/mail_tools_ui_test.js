"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
class Element{
  constructor(tag="div"){this.tagName=tag.toUpperCase();this.children=[];this.events={};this.dataset={};this.attributes={};this.value="";this.text="";this.hidden=false;}
  append(...items){this.children.push(...items);}
  replaceChildren(...items){this.children=[];this.text="";this.append(...items);}
  set textContent(value){this.text=String(value);this.children=[];}
  get textContent(){return this.text+this.children.map(item=>item.textContent).join("");}
  setAttribute(key,value){this.attributes[key]=String(value);}
  addEventListener(name,callback){this.events[name]=callback;}
  fire(name){return this.events[name]?.({preventDefault(){}});}
  reset(){}
}
function nodes(root){return root.children.flatMap(item=>[item,...nodes(item)]);}
function fixture(){
  const timers=new Map();let timer=0;
  const sandbox={window:{},document:{createElement:tag=>new Element(tag)},URLSearchParams,Date,clearTimeout:id=>timers.delete(id),setTimeout:callback=>{timers.set(++timer,callback);return timer;},PostPlusI18n:{language:"en",t:(key,args={})=>key.replace(/\{(\w+)\}/g,(all,name)=>args[name]??all)}};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,"../web/mail-tools.js"),"utf8"),sandbox);
  return {api:sandbox.window.PostPlusMailTools,timers};
}
async function run(){
  const f=fixture(),root=new Element(),changes=[],search=f.api.createSearch(root,{onChange:value=>changes.push(value)}),form=root.children[0],inputs=nodes(root);
  const q=inputs.find(item=>item.id==="mail-search-query"),selects=inputs.filter(item=>item.tagName==="SELECT"),dates=inputs.filter(item=>item.type==="date");
  q.value="验证码 + <b>";selects[0].value="all";selects[1].value="false";selects[2].value="true";dates[0].value="2026-10-01";dates[1].value="2026-10-15";
  form.fire("submit");assert.equal(search.active,true);assert.deepEqual(changes,[false]);
  const params=new URLSearchParams(search.query("INBOX").split("?")[1]);
  assert.equal(params.get("q"),"验证码 + <b>");assert.equal(params.get("folder"),"all");assert.equal(params.get("seen"),"false");assert.equal(params.get("has_attachment"),"true");assert.equal(params.get("before"),String(Date.parse("2026-10-16T00:00:00Z")/1000));
  search.show({has_more:true,offset:0,limit:50});const more=inputs.find(item=>item.textContent==="Load more");assert.equal(more.hidden,false);more.fire("click");assert.deepEqual(changes,[false,true]);assert.match(search.query("INBOX",true),/offset=50/);
  search.show({indexing:true,has_more:false});assert.match(root.textContent,/Indexing existing mail/);search.reset();assert.equal(search.active,false);assert.equal(q.value,"");
  const requests=[],panel=new Element(),delivery=f.api.createDelivery(panel,{request:url=>new Promise((resolve,reject)=>requests.push({url,resolve,reject}))});
  let pending=delivery.load("one");assert.equal(requests[0].url,"/api/messages/one/delivery-status");
  requests[0].resolve({recipients:[{recipient:"<b>user@example.com</b>",state:"retrying",last_error:"<script>error</script>",attempts:2,next_attempt:1700000000,events:[{state:"queued",created_at:1699999000}]}]});await pending;
  assert.equal(panel.hidden,false);assert.match(panel.textContent,/<script>error<\/script>/);assert.match(panel.textContent,/Retrying/);assert.equal(f.timers.size,1);
  const poll=[...f.timers.values()][0];f.timers.clear();pending=poll();requests.at(-1).resolve({recipients:[{recipient:"remote@example.com",state:"delivered",delivery_scope:"remote_mta",history:[{state:"delivered",at:1700000000}]}]});await pending;
  assert.match(panel.textContent,/Accepted by recipient server/);assert.match(panel.textContent,/does not confirm inbox placement/);assert.equal(f.timers.size,0);
  pending=delivery.load("stale");const stale=requests.at(-1);delivery.reset();stale.resolve({recipients:[{recipient:"private",state:"queued"}]});await pending;assert.equal(panel.hidden,true);assert.equal(panel.children.length,0);assert.equal(f.timers.size,0);
  pending=delivery.load("none");requests.at(-1).resolve({recipients:[]});await pending;assert.match(panel.textContent,/No delivery history/);delivery.dispose();assert.equal(panel.hidden,true);
  assert.doesNotMatch(fs.readFileSync(path.join(__dirname,"../web/mail-tools.js"),"utf8"),/innerHTML|localStorage|sessionStorage/);
  console.log("Mail tools UI checks passed: encoded search filters, inclusive dates, pagination/indexing state, delivery progress/history and stale/logout isolation.");
}
run().catch(error=>{console.error(error);process.exitCode=1;});
