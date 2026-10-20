"use strict";
// Exercise the real domain wizard and DNS component against a lifecycle API.
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
const rootPath=path.resolve(__dirname,".."),descendants=el=>el.children.flatMap(child=>[child,...descendants(child)]);
class Element {
  constructor(tag="div"){this.tagName=tag.toUpperCase();this.children=[];this.dataset={};this.attributes={};this.events=new Map();this.value="";this.hidden=false;this.disabled=false;this.open=false;this.className="";this.classList={toggle:(name,value)=>{const classes=new Set(this.className.split(" "));if(value)classes.add(name);else classes.delete(name);this.className=[...classes].join(" ");}};}
  set textContent(value){this.text=String(value);this.children=[];}
  get textContent(){return (this.text||"")+this.children.map(child=>child.textContent).join("");}
  append(...children){for(const child of children){child.parentElement=this;this.children.push(child);}}
  prepend(...children){for(const child of children)child.parentElement=this;this.children.unshift(...children);}
  replaceChildren(...children){this.children=[];this.append(...children);}
  setAttribute(key,value){this.attributes[key]=value;}
  getAttribute(key){return this.attributes[key];}
  addEventListener(name,handler){if(!this.events.has(name))this.events.set(name,[]);this.events.get(name).push(handler);}
  async fire(name,extra={}){for(const handler of this.events.get(name)||[])await handler({target:this,preventDefault(){},...extra});}
  click(){return this.fire("click");}
  focus(){this.focused=true;}
  select(){this.selected=true;}
  showModal(){this.open=true;}
  close(){this.open=false;this.fire("close");}
  remove(){if(this.parentElement)this.parentElement.children=this.parentElement.children.filter(item=>item!==this);}
  querySelectorAll(selector){return selector==="[data-i18n]"?descendants(this).filter(item=>item.dataset.i18n):[];}
}
const tick=()=>new Promise(resolve=>setImmediate(resolve));
function fixture(){
  const container=new Element(),requests=[],notices=[],saved=[],entries=new Map([["example.com",{domain:"example.com",primary:true,status:"active",dns_status:"unchecked",checked_at:"",can_activate:false,can_remove:false,dns:{}}]]);
  let revision=1,deferred=null,policyRevision="config-1";
  const document={createElement:tag=>new Element(tag),createTextNode:value=>{const el=new Element("text");el.textContent=value;return el;},documentElement:{lang:"en"},querySelectorAll:()=>[],dispatchEvent(){}};
  const sandbox={window:{},document,URL,location:{href:"https://example.com:8080/"},setTimeout,clearTimeout,localStorage:{getItem:()=>null,setItem(){}},CustomEvent:class{}};
  vm.runInNewContext(fs.readFileSync(path.join(rootPath,"web/i18n.js"),"utf8"),sandbox);sandbox.PostPlusI18n=sandbox.window.PostPlusI18n;
  for(const filename of ["admin-dns.js","admin-domains.js"]){vm.runInNewContext(fs.readFileSync(path.join(rootPath,"web",filename),"utf8"),sandbox);sandbox.PostPlusAdminDns=sandbox.window.PostPlusAdminDns;}
  const report=(domain,dns={})=>({ok:true,domain,hostname:"mail.example.com",outbound_mode:"direct",expected:{ipv4:"",ipv6:"",spf:"v=spf1 mx -all",dkim_name:"",dkim_type:"TXT",dkim_value:"",dmarc:"v=DMARC1; p=none",...dns},records:[{id:"mx",name:domain,host:"@",type:"MX",value:"10 mail.example.com.",observed:[],status:"unchecked"}],connectivity:[]});
  async function api(url,options={}){
    requests.push({url,...JSON.parse(JSON.stringify(options))});if(deferred){const next=deferred;deferred=null;return next(url,options);}
    const body=options.body||{},route=url.split("?")[0];
    if(route==="/api/admin/config"){
      if(options.method==="POST"){assert.equal(body.revision,policyRevision);policyRevision="config-2";return {ok:true,revision:policyRevision,admin_url:"https://admin.example.com:8080/",restart:{state:"pending"}};}
      return {ok:true,revision:policyRevision,values:{domain:"example.com",admin_hostname:"",webmail_shared_hostname:""},restart_available:true};
    }
    if(route==="/api/admin/domains"&&options.method!=="POST"){
      const query=new URL(url,"https://example.com").searchParams,all=[...entries.values()].filter(item=>item.domain.includes(query.get("q"))),offset=Number(query.get("offset")),limit=Number(query.get("limit"));
      return {ok:true,revision:String(revision),items:all.slice(offset,offset+limit).map(item=>({...item})),total:all.length,total_domains:entries.size,offset,limit,restart_required:false};
    }
    if(route==="/api/admin/domains/preview"){assert.equal(options.method,"POST");assert.ok(body.dns);return report(body.domain,body.dns);}
    assert.equal(options.method,"POST");assert.equal(body.revision,String(revision),"Every mutation uses the current revision");
    if(route==="/api/admin/domains")entries.set(body.domain,{domain:body.domain,primary:false,status:"pending",dns_status:"unchecked",checked_at:"",can_activate:false,can_remove:true,dns:{}});
    if(route==="/api/admin/domains/check"){
      assert.equal(body.expected,undefined,"DNS values use the backend dns contract");assert.ok(body.dns);entries.set(body.domain,{...entries.get(body.domain),can_activate:true,dns_status:"warnings",checked_at:"2026-10-20T12:00:00Z",dns:body.dns});revision++;
      return {ok:true,revision:String(revision),record:entries.get(body.domain),dns:{...report(body.domain,body.dns),checked_at:"2026-10-20T12:00:00Z",records:report(body.domain).records.map(record=>({...record,status:"matched",observed:[record.value]}))}};
    }
    if(route==="/api/admin/domains/activate"){assert.equal(entries.get(body.domain).can_activate,true);entries.set(body.domain,{...entries.get(body.domain),status:"active",can_activate:false});}
    if(route==="/api/admin/domains/remove")entries.delete(body.domain);
    revision++;return {ok:true,revision:String(revision),record:entries.get(body.domain),restart_required:route.endsWith("activate")||route.endsWith("remove")};
  }
  const component=sandbox.window.PostPlusAdminDomains.mount(container,{api,notice:text=>notices.push(text),onSaved:data=>saved.push(data)});
  const id=name=>descendants(container).find(item=>item.id===name),label=text=>descendants(container).find(item=>item.dataset.i18n===text),buttons=text=>descendants(container).filter(item=>item.tagName==="BUTTON"&&item.textContent===text);
  return {container,component,id,label,buttons,requests,entries,saved,notices,api:sandbox.window.PostPlusAdminDomains,defer:handler=>{deferred=handler;}};
}
async function main(){
  const delayed=fixture();await delayed.component.refresh();let finishLoad;
  delayed.defer(()=>new Promise(resolve=>{finishLoad=resolve;}));await delayed.id("domain-tab-portals").click();
  const policyInputs=["domain-admin-hostname","domain-shared-hostname","domain-shared-enabled"];
  for(const name of policyInputs)assert.equal(delayed.id(name).disabled,true,"Login address inputs are locked until their saved values arrive");
  assert.equal(delayed.buttons("Reload login addresses")[0].disabled,true);
  const pendingCount=delayed.requests.length;await delayed.id("domain-tab-portals").click();assert.equal(delayed.requests.length,pendingCount,"A second tab activation cannot start an overlapping policy load");
  finishLoad({ok:true,revision:"loaded",values:{domain:"example.com",admin_hostname:"admin.example.com",webmail_shared_hostname:""}});await tick();
  assert.equal(delayed.id("domain-admin-hostname").disabled,false);assert.equal(delayed.id("domain-shared-enabled").disabled,false);assert.equal(delayed.id("domain-shared-hostname").disabled,true,"Shared hostname stays disabled when shared access is off");
  delayed.id("domain-shared-enabled").checked=true;await delayed.id("domain-shared-enabled").fire("change");delayed.id("domain-shared-hostname").value="webmail.example.com";
  const delayedForm=delayed.id("domain-policy-save").parentElement.parentElement;await delayedForm.fire("input");assert.equal(delayed.component.hasUnsavedChanges(),true);
  let finishSave;delayed.defer(()=>new Promise(resolve=>{finishSave=resolve;}));const saving=delayedForm.fire("submit");
  for(const name of policyInputs)assert.equal(delayed.id(name).disabled,true,"Saving locks the exact hostnames being submitted");
  assert.equal(delayed.id("domain-policy-save").disabled,true);assert.equal(delayed.buttons("Reload login addresses")[0].disabled,true);
  finishSave({ok:true,revision:"saved"});await saving;for(const name of policyInputs)assert.equal(delayed.id(name).disabled,false);assert.equal(delayed.component.hasUnsavedChanges(),false);
  delayed.id("domain-shared-enabled").checked=false;await delayed.id("domain-shared-enabled").fire("change");let rejectSave;delayed.defer(()=>new Promise((resolve,reject)=>{rejectSave=reject;}));const rejected=delayedForm.fire("submit");rejectSave(new Error("Temporary failure"));await rejected;
  assert.equal(delayed.id("domain-admin-hostname").disabled,false);assert.equal(delayed.id("domain-shared-enabled").disabled,false);assert.equal(delayed.id("domain-shared-hostname").disabled,true,"A failed save restores the checkbox-dependent enabled state");delayed.component.dispose();
  const f=fixture();await f.component.refresh();
  assert.equal(f.buttons("Remove").length,0,"The first domain has no remove control");assert.equal(f.buttons("DNS details").length,1,"Backend active status renders as active");
  await f.id("domain-add").click();assert.equal(f.id("domain-wizard").open,true);f.id("new-mail-domain").value="bad domain";await f.id("domain-continue").click();assert.equal(f.requests.length,1,"Invalid domain does not mutate configuration");
  f.id("new-mail-domain").value=" Second.Example ";await f.id("domain-continue").click();await tick();
  assert.equal(f.entries.get("second.example").status,"pending");assert.equal(f.id("domain-activate").disabled,true);assert.equal(f.id("domain-continue").hidden,true);assert.equal(f.id("hosted-domain-dns-check").disabled,false);assert.ok(f.container.textContent.includes("Mail activation does not create DNS records or certificates"));
  f.id("hosted-domain-dns-ipv4").value="93.184.216.34";await f.id("hosted-domain-dns-ipv4").fire("input");
  await f.id("hosted-domain-dns-check").click();assert.equal(f.id("domain-activate").disabled,false);assert.equal(f.requests.at(-1).body.dns.ipv4,"93.184.216.34");
  await f.id("hosted-domain-dns-ipv4").fire("input");assert.equal(f.id("domain-activate").disabled,true,"Changed DNS expectations require another check");await f.id("hosted-domain-dns-check").click();await f.id("domain-activate").click();await tick();
  assert.equal(f.entries.get("second.example").status,"active");assert.equal(f.saved.length,1);assert.equal(f.saved[0].restart_required,true);assert.equal(f.id("domain-wizard").open,false);assert.equal(f.buttons("DNS details").length,2);
  await f.buttons("Remove")[0].click();assert.equal(f.id("domain-remove-dialog").open,true);f.id("domain-remove-confirm").value="wrong.example";await f.id("domain-remove-confirm").fire("input");assert.equal(f.buttons("Remove domain")[0].disabled,true);f.id("domain-remove-confirm").value="second.example";await f.id("domain-remove-confirm").fire("input");await f.buttons("Remove domain")[0].click();await tick();assert.equal(f.entries.has("second.example"),false);assert.ok(f.requests.some(request=>request.url==="/api/admin/domains/remove"&&request.method==="POST"));
  for(let i=0;i<125;i++)f.entries.set(`d${String(i).padStart(3,"0")}.example`,{domain:`d${String(i).padStart(3,"0")}.example`,status:"active",dns_status:"unchecked",primary:false,can_remove:true});
  await f.component.refresh();assert.equal(f.buttons("DNS details").length,25);await f.id("domains-next").click();await tick();assert.match(f.requests.at(-1).url,/offset=25&limit=25/);assert.equal(f.buttons("DNS details").length,25);assert.match(f.container.textContent,/126 hosted domains/);
  f.id("domains-search").value="d124";await f.id("domains-search").fire("input");await new Promise(resolve=>setTimeout(resolve,275));assert.equal(f.buttons("DNS details").length,1);assert.equal(f.id("domains-next").disabled,true);assert.ok(f.container.textContent.includes("d124.example"));
  await f.id("domain-tab-portals").click();await tick();assert.equal(f.id("domain-admin-hostname").value,"example.com");assert.equal(f.id("domain-shared-hostname").disabled,true);f.id("domain-shared-enabled").checked=true;await f.id("domain-shared-enabled").fire("change");assert.equal(f.id("domain-shared-hostname").disabled,false);f.id("domain-admin-hostname").value="admin.example.com";f.id("domain-shared-hostname").value="mailbox.example.com";await f.id("domain-policy-save").parentElement.parentElement.fire("submit");assert.deepEqual(f.requests.at(-1).body.values,{admin_hostname:"admin.example.com",webmail_shared_hostname:"mailbox.example.com"});assert.equal(f.saved.at(-1).restart.state,"pending");
  let resolve;f.defer(()=>new Promise(done=>{resolve=done;}));const reload=f.component.refresh();f.component.dispose();resolve({ok:true,revision:"9",items:[],total:0});await reload;assert.equal(f.container.children.length,0,"Late API replies never restore signed-out domain UI");
  const source=fs.readFileSync(path.join(rootPath,"web/setup.js"),"utf8");assert.match(source,/\["additional_domains","mail_domains","admin_hostname","webmail_shared_hostname"\]/,"First-run setup stays single-domain");
  console.log("PASS domain lifecycle UI: pending wizard, saved DNS, activation gates, restart handoff, protected primary, safe removal, 126-domain pagination/search, portal policy and stale reply disposal");
}
main().catch(error=>{console.error(error);process.exitCode=1;});
