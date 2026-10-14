"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
const root=path.resolve(__dirname,"..");
const descendants=element=>element.children.flatMap(child=>[child,...descendants(child)]);
class Element {
  constructor(tag="div"){this.tagName=tag.toUpperCase();this.children=[];this.dataset={};this.attributes={};this.events=new Map();this.value="";this.hidden=false;this.disabled=false;this.textContent="";}
  get textContent(){return this.text+this.children.map(child=>child.textContent).join("");}
  set textContent(value){this.text=String(value);this.children=[];}
  append(...items){for(const item of items){item.parentElement=this;this.children.push(item);}}
  insertBefore(item,before){item.parentElement=this;const index=this.children.indexOf(before);this.children.splice(index<0?this.children.length:index,0,item);}
  replaceChildren(...items){this.children=[];this.append(...items);}
  setAttribute(name,value){this.attributes[name]=value;}
  getAttribute(name){return this.attributes[name];}
  removeAttribute(name){delete this.attributes[name];}
  addEventListener(name,listener){if(!this.events.has(name))this.events.set(name,[]);this.events.get(name).push(listener);}
  removeEventListener(name,listener){this.events.set(name,(this.events.get(name)||[]).filter(handler=>handler!==listener));}
  async fire(name){for(const listener of this.events.get(name)||[])await listener({target:this});}
  select(){this.selected=true;}
  focus(){this.focused=true;}
  checkValidity(){return true;}
  closest(selector){for(let parent=this;parent;parent=parent.parentElement){if(selector==="details"&&parent.tagName==="DETAILS")return parent;if(selector===".mail-clients"&&parent.className?.split(" ").includes("mail-clients"))return parent;}return null;}
  querySelector(selector){return this.querySelectorAll(selector)[0];}
  querySelectorAll(selector){const all=descendants(this);if(selector==="[data-i18n]")return all.filter(item=>item.dataset.i18n);let match=/^\[data-config-key="(.+)"\]$/.exec(selector);if(match)return all.filter(item=>item.dataset.configKey===match[1]);match=/^\[data-i18n-(.+)\]$/.exec(selector);return match?all.filter(item=>item.attributes[`data-i18n-${match[1]}`]):[];}
}
function fixture(config){
  let current=config;
  const element=new Element(),sandbox={window:{},URL,navigator:{},document:{createElement:tag=>new Element(tag),documentElement:{lang:"en"},querySelectorAll:()=>[],dispatchEvent(){},addEventListener(){}},localStorage:{getItem:()=>null,setItem(){}},CustomEvent:class{constructor(type){this.type=type;}}};
  for(const name of ["i18n","size","mail-clients","settings"]){vm.runInNewContext(fs.readFileSync(path.join(root,`web/${name}.js`),"utf8"),sandbox);sandbox[{i18n:"PostPlusI18n",size:"PostPlusSize","mail-clients":"PostPlusMailClients",settings:"PostPlusSettings"}[name]]=sandbox.window[{i18n:"PostPlusI18n",size:"PostPlusSize","mail-clients":"PostPlusMailClients",settings:"PostPlusSettings"}[name]];}
  const api=sandbox.PostPlusMailClients,component=api.create(element,{readConfig:()=>current,prefix:"test"});
  const id=name=>descendants(element).find(item=>item.id===`test-${name}`);
  return {api,component,element,sandbox,id,set(value){current=value;component.render();}};
}
const secure={domain:"example.com",mail_hostname:"mail.example.com",bind:"0.0.0.0",allow_insecure_auth:false,tls_certificate:"/cert.pem",tls_private_key:"/key.pem",ports:{smtp:2525,pop3:1110,imap:1143,web:443,submission:1587,smtps:1465,pop3s:1995,imaps:1993,admin:8081,auth:9091}};
const plain=value=>JSON.parse(JSON.stringify(value));
async function run(){
  const f=fixture(secure),model=f.api.model(secure);
  assert.equal(model.webUrl,"https://mail.example.com/");
  assert.equal(model.rows.find(row=>row.id==="imap").port,1143,"Custom saved ports stay intact");
  assert.equal(model.rows.find(row=>row.id==="submission").security,"STARTTLS");
  assert.ok(model.rows.every(row=>row.username==="yourname@example.com"));
  assert.equal(model.records.find(record=>record.host==="_submission._tcp").value,"0 1 1587 mail.example.com.");
  assert.equal(model.records.find(record=>record.host==="_submissions._tcp").value,"0 1 1465 mail.example.com.");
  assert.ok(model.records.some(record=>record.host==="_autodiscover._tcp"));
  assert.ok(model.records.every(record=>record.type==="SRV"),"Do not propose aliases without certificate coverage");
  assert.equal(model.autoconfigUrl,"https://mail.example.com/.well-known/autoconfig/mail/config-v1.1.xml");
  assert.equal(model.rows.some(row=>row.id==="smtp"),false,"Mail apps should use authenticated submission, not reception 25");
  const disabled=f.api.model({...secure,ports:{...secure.ports,submission:0,smtps:0,pop3s:0,imaps:0}});
  assert.equal(disabled.rows.some(row=>row.direction==="Outgoing mail"),false);
  assert.equal(disabled.records.some(record=>record.host==="_autodiscover._tcp"),false);
  for(const changes of [{tls_private_key:""},{tls_certificate:""},{tls_certificate:"",tls_private_key:""}]){
    const incomplete=f.api.model({...secure,...changes});assert.equal(incomplete.records.length,0);assert.equal(incomplete.rows.length,0,"Network passwords require TLS, and dedicated ports need both files");
  }
  assert.equal(f.api.model({...secure,bind:"127.0.0.1"}).records.length,0,"Local services cannot be advertised as publicly reachable");
  const local=f.api.model({...secure,bind:"127.0.0.1",allow_insecure_auth:true,tls_certificate:"",tls_private_key:"",ports:{smtp:2525,pop3:1110,imap:1143,web:8080}});
  assert.equal(local.webUrl,"http://127.0.0.1:8080/");assert.equal(local.rows.find(row=>row.id==="smtp").hostname,"127.0.0.1");
  assert.equal(f.api.model({...secure,ports:{...secure.ports,web:8443}}).discovery,false,"Custom HTTPS port supports manual configuration without a misleading discovery record");
  assert.equal(f.api.model({...secure,mail_hostname:"",domain:"mail.example.com"}).hostname,"mail.example.com","Do not duplicate the mail prefix");
  assert.equal(f.api.model({...secure,domain:"localhost"}).records.length,0);
  assert.deepEqual(plain(f.api.standardPorts(true)),{smtp:25,pop3:110,imap:143,web:443,submission:587,smtps:465,pop3s:995,imaps:993});
  assert.equal(Object.hasOwn(f.api.standardPorts(true),"admin"),false,"Preset leaves administration and internal services alone");
  assert.deepEqual(plain(f.api.standardPorts(false)),{smtp:25,pop3:110,imap:143,web:80,submission:587,smtps:465,pop3s:995,imaps:993});
  const presetWithoutTls={...secure,tls_certificate:"",tls_private_key:"",ports:f.api.standardPorts(false)};
  assert.equal(f.api.model(presetWithoutTls).rows.length,0,"Configured dedicated standard ports stay inactive before certificate/key are supplied");
  assert.equal(f.api.model(presetWithoutTls).records.length,0);
  assert.equal(f.api.model({...presetWithoutTls,tls_certificate:"/cert.pem",tls_private_key:"/key.pem"}).rows.find(row=>row.id==="submission").port,587,"Adding TLS activates the configured standard submission port");
  assert.doesNotMatch(f.id("copy").value,/\/key.pem|\/cert.pem/);assert.match(f.id("copy").value,/mail.example.com:1587/);
  await f.id("copy-button").fire("click");assert.equal(f.id("copy").selected,true,"Clipboard failure selects a manual fallback");
  let copied="";f.sandbox.navigator.clipboard={writeText:async text=>{copied=text;}};await f.id("copy-button").fire("click");assert.equal(copied,f.id("copy").value);assert.match(f.element.textContent,/configuration copied/);
  let resolve;f.sandbox.navigator.clipboard={writeText:()=>new Promise(done=>{resolve=done;})};const pending=f.id("copy-button").fire("click");f.set({...secure,mail_hostname:"changed.example.com"});resolve();await pending;assert.doesNotMatch(f.element.textContent,/configuration copied/);assert.match(f.id("copy").value,/changed.example.com/);
  f.sandbox.PostPlusI18n.setLanguage("zh-CN");f.component.translate();assert.match(f.element.textContent,/连接安全性|邮箱客户端可选/);assert.doesNotMatch(f.element.textContent,/Client settings follow/);
  f.component.dispose();assert.equal(f.element.children.length,0);
  // Use the production settings editor: filling a preset must remain a draft until read/save.
  const settingsRoot=new Element(),schema=[{key:"domain",group:"general",type:"text",label:"Mail domain"},{key:"mail_hostname",group:"network",type:"text",label:"Mail server hostname"},{key:"tls_certificate",group:"security",type:"text",label:"TLS certificate file"},{key:"tls_private_key",group:"security",type:"text",label:"TLS private key file"},...Object.keys(secure.ports).map(name=>({key:"ports."+name,group:"network",type:"number",label:name,min:["submission","smtps","pop3s","imaps"].includes(name)?0:1,max:65535}))];
  const changes=[];
  const editor=f.sandbox.PostPlusSettings.create(settingsRoot,schema,secure,{prefix:"config",mailClients:true,onChange:count=>changes.push(count)});
  assert.equal(changes.at(-1),0);
  assert.deepEqual(plain(editor.read()),{},"Loading existing settings does not change custom ports");
  const preset=descendants(settingsRoot).find(item=>item.id==="config-standard-ports");assert.ok(preset);await preset.fire("click");
  const changed=plain(editor.read());assert.equal(changed.ports.smtp,25);assert.equal(changed.ports.web,undefined,"Unchanged web443 is omitted from the save patch");assert.equal(changed.ports.submission,587);assert.equal(changed.ports.admin,undefined);assert.equal(changed.ports.auth,undefined);assert.equal(secure.ports.smtp,2525,"Preset never mutates the loaded configuration object");
  assert.equal(changes.at(-1),7,"Programmatic preset updates the count by individual changed ports");
  editor.dispose();
  const draftRoot=new Element(),draftSchema=[
    {key:"domain",group:"general",type:"text",label:"Mail domain"},
    {key:"max_message_bytes",group:"storage",type:"number",unit:"bytes",label:"Message size",min:1,max:104857600},
    {key:"smarthost_password",group:"delivery",type:"password",label:"Relay password"},
    {key:"allow_insecure_auth",group:"security",type:"boolean",label:"Allow insecure authentication"},
    {key:"test_lines",group:"general",type:"lines",label:"Lines"},
    {key:"test_json",group:"general",type:"json",label:"JSON"}];
  const counts=[],draft=f.sandbox.PostPlusSettings.create(draftRoot,draftSchema,{domain:"example.com",max_message_bytes:1048576,allow_insecure_auth:false,test_lines:["a","b"],test_json:{a:1}},{secretStatus:{smarthost_password:true},onChange:count=>counts.push(count)});
  const field=key=>descendants(draftRoot).find(item=>item.dataset.configKey===key);
  field("domain").value=" example.com ";field("test_lines").value=" a \n b \n";field("test_json").value='{ "a": 1 }';draft.notify();assert.equal(counts.at(-1),0,"Whitespace-equivalent typed values are unchanged");assert.deepEqual(plain(draft.read()),{});
  const unit=descendants(draftRoot).find(item=>item.id==="settings-max_message_bytes-unit");unit.value="KiB";await unit.fire("change");draft.notify();assert.equal(field("max_message_bytes").value,"1024");assert.equal(counts.at(-1),0,"Changing a display unit preserves byte equality");
  field("max_message_bytes").value="oops";await draftRoot.fire("input");assert.equal(counts.at(-1),1);assert.equal(field("max_message_bytes").focused,undefined,"Counting an invalid draft does not validate or move focus");
  field("max_message_bytes").value="1024";field("allow_insecure_auth").value="true";field("smarthost_password").value="new secret";draft.notify();assert.equal(counts.at(-1),2);
  const clear=descendants(draftRoot).find(item=>item.type==="checkbox");clear.checked=true;await clear.fire("change");draft.notify();assert.equal(counts.at(-1),2,"Clearing and editing the same secret counts as one setting");assert.equal(plain(draft.read()).clear_smarthost_password,true);
  clear.checked=false;await clear.fire("change");field("allow_insecure_auth").value="false";draft.notify();assert.equal(counts.at(-1),0,"Reverting settings returns to zero");
  const previous=counts.length;draft.dispose();await draftRoot.fire("input");assert.equal(counts.length,previous,"Disposed editor stops emitting draft counts");
  for(const name of ["setup","admin"]){const html=fs.readFileSync(path.join(root,`web/${name}.html`),"utf8");assert.equal(html.split('src="/mail-clients.js"').length-1,1);}
  console.log("Mail client UI checks passed: preserved ports, explicit preset, enabled TLS services, SRV/discovery, local mode, copy fallback, localization and stale replies.");
}
run().catch(error=>{console.error(error);process.exitCode=1;});
