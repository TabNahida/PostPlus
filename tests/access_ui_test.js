"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
const root=path.resolve(__dirname,".."),read=name=>fs.readFileSync(path.join(root,"web",name),"utf8");
const descendants=node=>node.children.flatMap(child=>[child,...descendants(child)]);
class Element {
  constructor(tag="div"){this.tagName=tag.toUpperCase();this.children=[];this.events=new Map();this.attributes={};this.value="";this.hidden=false;this.disabled=false;this.checked=false;this.text="";this.parentNode=null;}
  append(...nodes){for(const node of nodes){if(node.parentNode)node.remove();node.parentNode=this;this.children.push(node);}}
  replaceChildren(...nodes){for(const child of this.children)child.parentNode=null;this.children=[];this.text="";this.append(...nodes);}
  set textContent(value){this.replaceChildren();this.text=String(value);}
  get textContent(){return this.text+this.children.map(child=>child.textContent).join("");}
  setAttribute(name,value){this.attributes[name]=String(value);}
  getAttribute(name){return this.attributes[name]??null;}
  addEventListener(name,callback){if(!this.events.has(name))this.events.set(name,[]);this.events.get(name).push(callback);}
  async fire(name){for(const callback of this.events.get(name)||[])await callback({currentTarget:this,preventDefault(){}});}
  remove(){if(this.parentNode){this.parentNode.children=this.parentNode.children.filter(child=>child!==this);this.parentNode=null;}}
  focus(){this.focused=true;}
  select(){this.selected=true;}
  showModal(){this.open=true;}
  close(){this.open=false;return this.fire("close");}
}
const tick=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};}
function fixture(file){
  const requests=[],notices=[],copies=[],controls=new Map(),historyCalls=[],order=[];
  const document={body:new Element("body"),createElement:tag=>new Element(tag),getElementById(id){if(!controls.has(id))controls.set(id,new Element(id.endsWith("form")?"form":"div"));return controls.get(id);}};
  const forbiddenStorage={getItem(){throw new Error("Secrets must not use persistent storage");},setItem(){throw new Error("Secrets must not use persistent storage");},removeItem(){throw new Error("Secrets must not use persistent storage");}};
  const sandbox={window:{},document,navigator:{clipboard:{writeText:async value=>{copies.push(value);}}},location:{hash:"",pathname:"/register",search:"?untrusted=1"},history:{replaceState(...args){historyCalls.push(args);order.push("history");}},localStorage:forbiddenStorage,sessionStorage:forbiddenStorage,PostPlusI18n:{language:"en",t:(key,args={})=>{for(const [name,value]of Object.entries(args))key=key.replaceAll("{"+name+"}",String(value));return key;},error:value=>value.error||"Request failed"}};
  const api=(url,options)=>{const d=deferred();requests.push({url,options,...d});return d.promise;};
  sandbox.fetch=(url,options)=>{order.push("fetch");return api(url,options);};
  vm.createContext(sandbox);
  const run=()=>vm.runInContext(read(file),sandbox,{filename:file});
  const element=new Element();
  return {sandbox,document,controls,element,requests,notices,copies,historyCalls,order,api,run,notice:(...args)=>notices.push(args),id:id=>document.getElementById(id),find:label=>descendants(element).find(node=>node.getAttribute("aria-label")===label),button:label=>descendants(element).find(node=>node.tagName==="BUTTON"&&node.textContent===label)};
}
const keyList={permissions:["mailbox:read","mailbox:write","mailbox:send","codes:read"],api_keys:[]};
async function keyChecks(){
  const f=fixture("key-permissions.js");f.run();const api=f.sandbox.window.PostPlusKeyPermissions;
  const editorRoot=new Element(),editor=api.editor(editorRoot,["mailbox:read","codes:read","mailbox:send"],["codes:read","unknown:write"]);
  assert.deepEqual([...editor.value()],["codes:read"],"Grant editor returns only selected catalog permissions");
  editorRoot.children[0].children[0].checked=true;assert.deepEqual([...editor.value()],["mailbox:read","codes:read"]);editor.clear();assert.deepEqual([...editor.value()],[]);
  let saved;api.editDialog({name:"<script>literal</script>",permissions:["codes:read"]},keyList.permissions,async selected=>{saved=[...selected];});
  const dialog=f.document.body.children[0],checks=descendants(dialog).filter(node=>node.type==="checkbox");checks.find(node=>node.value==="mailbox:send").checked=true;
  await descendants(dialog).find(node=>node.tagName==="FORM").fire("submit");assert.deepEqual(saved,["mailbox:send","codes:read"]);assert.equal(f.document.body.children.length,0);assert.ok(checks.every(node=>!node.checked));
  const component=api.mount(f.element,{api:f.api,onError:f.notice});f.requests[0].resolve(keyList);await tick();
  const form=descendants(f.element).find(node=>node.tagName==="FORM"),name=f.find("Key name"),output=f.find("API key"),result=output.parentNode;
  name.value="  integration  ";const pending=form.fire("submit"),request=f.requests.at(-1),response={key:"pp_mail_secret_once",api_key:{id:1}};
  assert.equal(request.options.method,"POST");assert.equal(request.options.body.name,"integration");assert.deepEqual([...request.options.body.permissions],["codes:read"]);assert.equal(request.options.body.expires_in_days,90);
  request.resolve(response);await tick();assert.equal(response.key,"");assert.equal(output.value,"pp_mail_secret_once");assert.equal(result.hidden,false);
  f.requests.at(-1).resolve(keyList);await pending;await f.button("Copy API key").fire("click");assert.deepEqual(f.copies,["pp_mail_secret_once"]);assert.equal(output.selected,true);
  await f.button("Done").fire("click");assert.equal(output.value,"");assert.equal(result.hidden,true);
  name.value="logout pending";const stale=form.fire("submit"),late=f.requests.at(-1),lateResponse={key:"pp_mail_late_secret"};component.dispose();late.resolve(lateResponse);await stale;
  assert.equal(lateResponse.key,"");assert.equal(output.value,"");assert.equal(f.element.children.length,0,"Disposed key pane cannot reveal a late one-time key");
}
const invitation=(name="current")=>({id:1,name,localpart:"",domain:"example.com",uses:0,max_uses:1,active:true,expires_at:2000000000});
const resolveAccess=(requests,inviteName="current",pattern="sales-*")=>{for(const request of requests)request.resolve(request.url.endsWith("/invitations")?{invitations:[invitation(inviteName)]}:{rules:[{id:1,pattern,domain:"example.com",destination:"owner@example.com"}]});};
async function invitationChecks(){
  const f=fixture("admin-access.js");f.run();const component=f.sandbox.window.PostPlusAdminAccess.mount(f.element,{api:f.api,notice:f.notice});resolveAccess(f.requests);await tick();
  const form=f.find("Invitation name").parentNode.parentNode;f.find("Invitation name").value="  friend  ";f.find("Mailbox name (optional)").value="  member  ";
  const pending=form.fire("submit"),request=f.requests.at(-1),response={registration_url:"https://mail.example.com/register#pp_inv_once"};
  assert.equal(request.options.method,"POST");assert.equal(request.options.body.name,"friend");assert.equal(request.options.body.localpart,"member");assert.equal(request.options.body.expires_in_days,7);assert.equal(request.options.body.max_uses,1);
  request.resolve(response);await tick();const output=f.find("Invitation link");assert.equal(response.registration_url,"");assert.match(output.value,/#pp_inv_once$/);f.requests.at(-1).resolve({invitations:[]});await pending;
  await f.button("Copy invitation link").fire("click");assert.match(f.copies[0],/#pp_inv_once$/);await f.button("Done").fire("click");assert.equal(output.value,"");assert.equal(output.parentNode.hidden,true);
  const late=form.fire("submit"),lateRequest=f.requests.at(-1),lateResponse={registration_url:"https://mail.example.com/register#late_secret"};component.dispose();lateRequest.resolve(lateResponse);await late;
  assert.equal(lateResponse.registration_url,"");assert.equal(output.value,"");assert.equal(f.element.children.length,0);
}
async function accessListOrderingChecks(){
  const f=fixture("admin-access.js");f.run();const component=f.sandbox.window.PostPlusAdminAccess.mount(f.element,{api:f.api,notice:f.notice});const old=f.requests.slice(),refresh=component.refresh(),newer=f.requests.slice(2);
  resolveAccess(newer,"newest invitation","newest-*");await refresh;resolveAccess(old,"stale invitation","stale-*");await tick();
  assert.match(f.element.textContent,/newest invitation/);assert.match(f.element.textContent,/newest-\*/);assert.doesNotMatch(f.element.textContent,/stale invitation|stale-\*/,"Older refresh cannot overwrite newer lists");
  const pending=component.refresh(),requests=f.requests.slice(-2);component.dispose();resolveAccess(requests,"after logout");await pending;assert.equal(f.element.children.length,0);
}
async function invitationClipboardDisposalChecks(){
  const f=fixture("admin-access.js");f.run();const component=f.sandbox.window.PostPlusAdminAccess.mount(f.element,{api:f.api,notice:f.notice});resolveAccess(f.requests);await tick();
  const form=f.find("Invitation name").parentNode.parentNode,pending=form.fire("submit");f.requests.at(-1).resolve({registration_url:"https://mail.example.com/register#secret"});await tick();f.requests.at(-1).resolve({invitations:[]});await pending;
  const clipboard=deferred();f.sandbox.navigator.clipboard.writeText=()=>clipboard.promise;const copy=f.button("Copy invitation link").fire("click");component.dispose();clipboard.resolve();await copy;
  assert.equal(f.notices.length,0,"Detached invitation pane cannot emit delayed clipboard notices");
}
async function accountOrganizationChecks(){
  const f=fixture("admin-access.js"),actions=new Element(),refreshes=[];f.run();
  const component=f.sandbox.window.PostPlusAdminAccess.mount(f.element,{api:f.api,notice:f.notice,inviteActions:actions,afterDelete:async()=>refreshes.push(true)});
  resolveAccess(f.requests);await tick();
  assert.equal(actions.children[0].textContent,"Invite to mailbox","Invitation entry belongs beside Create user");
  const forwarding=descendants(f.element).find(node=>node.tagName==="DETAILS");assert.equal(Boolean(forwarding.open),false,"Forwarding rules start collapsed");assert.ok(descendants(forwarding).some(node=>node.tagName==="TABLE"));
  const inviteDialog=descendants(f.element).find(node=>node.tagName==="DIALOG");assert.ok(!inviteDialog.open);await actions.children[0].fire("click");assert.equal(inviteDialog.open,true);f.requests.at(-1).resolve({invitations:[]});await tick();
  const inviteForm=f.find("Invitation name").parentNode.parentNode,pending=inviteForm.fire("submit"),late=f.requests.at(-1),response={registration_url:"https://mail.example.com/register#must-clear-on-close"};
  await f.button("Close").fire("click");late.resolve(response);await pending;assert.equal(response.registration_url,"");assert.equal(f.find("Invitation link").value,"","Closing invitations clears late one-time links");
  component.deleteAccount({username:"delete@localhost",deletion_pending:false});const confirm=f.find("Type the complete email address to confirm"),form=confirm.parentNode.parentNode.parentNode;
  assert.equal(f.button("Delete account").disabled,true);confirm.value="different@localhost";await confirm.fire("input");assert.equal(f.button("Delete account").disabled,true);await form.fire("submit");assert.notEqual(f.requests.at(-1).url,"/api/admin/users");
  confirm.value="DELETE@localhost";await confirm.fire("input");assert.equal(f.button("Delete account").disabled,false);
  const deleting=form.fire("submit"),request=f.requests.at(-1);assert.equal(request.url,"/api/admin/users");assert.equal(request.options.method,"DELETE");assert.equal(request.options.body.username,"delete@localhost");assert.equal(request.options.body.confirm_username,"DELETE@localhost");
  request.resolve({ok:true});await tick();f.requests.at(-1).resolve({rules:[]});await deleting;assert.equal(refreshes.length,1);assert.equal(confirm.value,"");
  component.dispose();assert.equal(actions.children.length,0);assert.equal(f.element.children.length,0);
}
function accountSearchChecks(){
  const f=fixture("admin-access.js"),source=read("admin.js"),start=source.indexOf("function renderUsers()"),end=source.indexOf('$("users-search").addEventListener',start);
  f.document.createDocumentFragment=()=>new Element();
  Object.assign(f.sandbox,{$:f.id,t:f.sandbox.PostPlusI18n.t,element:(tag,className,text)=>{const node=new Element(tag);node.className=className||"";if(text!==undefined)node.textContent=text;return node;},state:{user:{username:"root@localhost"}},usersData:[{username:"root@localhost",admin:true},{username:"alice@localhost",admin:false},{username:"pending@localhost",admin:false,deletion_pending:true}],openUserDialog(){},openInspection(){},openQuota(){},accessControl:{deleteAccount(){}}});
  vm.runInContext(source.slice(start,end)+"renderUsers();",f.sandbox);
  const body=f.id("users-body");assert.match(body.textContent,/root@localhost.*alice@localhost.*pending@localhost/);assert.equal(f.id("users-count").textContent,"3 of 3 accounts");
  assert.ok(descendants(body).find(node=>node.getAttribute("aria-label")==="Delete account root@localhost").disabled,"Current/last administrator deletion is disabled");
  f.id("users-search").value="ALIce";vm.runInContext("renderUsers();",f.sandbox);assert.match(body.textContent,/alice@localhost/);assert.doesNotMatch(body.textContent,/root@localhost|pending@localhost/);assert.equal(f.id("users-count").textContent,"1 of 3 accounts");
  f.id("users-search").value="nobody";vm.runInContext("renderUsers();",f.sandbox);assert.equal(f.id("users-empty").hidden,false);assert.equal(f.id("users-count").textContent,"0 of 3 accounts");
  assert.match(read("admin.html"),/<details id="accounts-panel"[^>]* open>/,"Accounts table is expanded by default and collapsible");
}
function registrationFixture(token){
  const f=fixture("register.js");f.sandbox.location.hash="#"+token;f.id("register-form").hidden=true;f.id("register-login").hidden=true;f.run();return f;
}
const http=result=>({ok:true,json:async()=>result});
async function registrationChecks(){
  const token="pp_inv_"+"a".repeat(64),f=registrationFixture(token);assert.deepEqual(f.historyCalls,[[null,"","/register"]]);assert.deepEqual(f.order,["history","fetch"]);
  const inspect=f.requests[0];assert.equal(inspect.url,"/api/public/invitations/inspect");assert.equal(inspect.options.method,"POST");assert.equal(inspect.options.credentials,"omit");assert.equal(inspect.options.cache,"no-store");assert.deepEqual(JSON.parse(inspect.options.body),{token});assert.ok(!inspect.url.includes(token));
  inspect.resolve(http({ok:true,domain:"example.com",localpart:"reserved",policy:{min_length:12,require_digit:true}}));await tick();assert.equal(f.id("register-form").hidden,false);assert.equal(f.id("register-localpart").value,"reserved");assert.equal(f.id("register-localpart").readOnly,true);assert.match(f.id("register-policy").textContent,/Minimum 12 characters.*Require a digit/);
  f.id("register-password").value="notmatching";f.id("register-confirm").value="different";await f.id("register-form").fire("submit");assert.equal(f.requests.length,1);assert.match(f.id("register-error").textContent,/Passwords do not match/);
  f.id("register-password").value=f.id("register-confirm").value="Test!Password123";f.id("register-localpart").value=" reserved ";const pending=f.id("register-form").fire("submit"),redeem=f.requests.at(-1);await f.id("register-form").fire("submit");assert.equal(f.requests.length,2,"Busy form sends a single redeem request");
  assert.equal(redeem.url,"/api/public/invitations/redeem");assert.deepEqual(JSON.parse(redeem.options.body),{token,localpart:"reserved",password:"Test!Password123"});assert.equal(redeem.options.credentials,"omit");
  redeem.resolve(http({ok:true,username:"reserved@example.com"}));await pending;assert.equal(f.id("register-password").value,"");assert.equal(f.id("register-confirm").value,"");assert.equal(f.id("register-form").hidden,true);assert.equal(f.id("register-login").hidden,false);assert.match(f.id("register-status").textContent,/reserved@example.com is ready/);
  await f.id("register-form").fire("submit");assert.equal(f.requests.length,2,"Successful registration clears its token");
  for(const invalid of ["",token.toUpperCase(),"pp_inv_"+"a".repeat(63),"pp_inv_<script>"]){const bad=registrationFixture(invalid);await tick();assert.equal(bad.requests.length,0);assert.equal(bad.id("register-form").hidden,true);assert.match(bad.id("register-error").textContent,/invalid, expired/);await bad.id("register-form").fire("submit");assert.equal(bad.requests.length,0);}
  const failed=registrationFixture(token);failed.requests[0].resolve({ok:false,json:async()=>({ok:false,error:"Expired invitation"})});await tick();assert.equal(failed.id("register-form").hidden,true);assert.equal(failed.id("register-status").textContent,"");assert.equal(failed.id("register-error").textContent,"Expired invitation");await failed.id("register-form").fire("submit");assert.equal(failed.requests.length,1);
}
(async()=>{let failures=0;for(const [name,check]of Object.entries({keyChecks,invitationChecks,accessListOrderingChecks,invitationClipboardDisposalChecks,accountOrganizationChecks,accountSearchChecks,registrationChecks})){try{await check();console.log(name+" passed");}catch(error){failures++;console.error(name+" failed:",error);}}if(failures)process.exitCode=1;else console.log("Access UI checks passed: exact grants, one-time secret clearing, disposed/stale replies, invitation organization, account search/deletion confirmation and private registration requests.");})();
