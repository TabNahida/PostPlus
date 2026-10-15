"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
const descendants=node=>node.children.flatMap(child=>[child,...descendants(child)]);
class Element {
  constructor(tag="div"){this.tagName=tag.toUpperCase();this.children=[];this.dataset={};this.attributes={};this.events={};this.value="";this.hidden=false;this.disabled=false;this.checked=false;this.text="";this.innerHTML="";const classes=new Set();this.classList={toggle(name,value){if(value)classes.add(name);else classes.delete(name);},add:name=>classes.add(name),remove:name=>classes.delete(name),contains:name=>classes.has(name)};}
  append(...nodes){this.children.push(...nodes);for(const node of nodes)node.parentElement=this;}
  replaceChildren(...nodes){this.children=[];this.text="";this.innerHTML="";this.append(...nodes);}
  set textContent(value){this.text=String(value);this.children=[];this.innerHTML=String(value);}
  get textContent(){return this.text+this.children.map(child=>child.textContent).join("");}
  setAttribute(name,value){this.attributes[name]=String(value);}
  removeAttribute(name){delete this.attributes[name];}
  getAttribute(name){return this.attributes[name]??null;}
  addEventListener(name,callback){this.events[name]=callback;}
  fire(name,options={}){return this.events[name]?.({currentTarget:this,target:this,preventDefault(){},...options});}
  focus(){this.focused=true;}
  showModal(){this.open=true;}
  close(){this.open=false;}
  querySelector(){return new Element("button");}
  querySelectorAll(selector){return selector==="button"?descendants(this).filter(node=>node.tagName==="BUTTON"):[];}
  contains(node){return node===this || descendants(this).includes(node);}
  reset(){}
}
function fixture(){
  const controls=new Map(),events=new Map(),id=name=>document.getElementById(name);
  const document={getElementById(name){if(!controls.has(name))controls.set(name,new Element());return controls.get(name);},createElement:tag=>new Element(tag),createElementNS:(ns,tag)=>new Element(tag),createDocumentFragment:()=>new Element(),querySelector:()=>new Element(),querySelectorAll:()=>[],addEventListener:(event,callback)=>events.set(event,callback),execCommand(){}};
  id("compose-form").reset=()=>{for(const name of ["to","cc","bcc","subject","text"])id("compose-"+name).value="";id("compose-format").checked=false;};
  const sandbox={document,window:{},navigator:{},fetch:()=>new Promise(()=>{}),setTimeout:()=>1,clearTimeout(){},PostPlusI18n:{language:"en",t:(key,args={})=>key.replace(/\{(\w+)\}/g,(all,name)=>args[name]??all),error:value=>value.error || "error"},PostPlusAddress:{create:()=>({setDomain(){},address(){return "writer@example.test";}})},PostPlusSize:{format:value=>String(value)},PostPlusMailReader:{create:()=>({clear(){},show(){}}),sanitize:html=>({html:html.replace(/<script>[\s\S]*?<\/script>/g,""),text:html.replace(/<[^>]*>/g,"")}),bodySource:value=>value},PostPlusVerificationCode:{create:()=>({load(){},reset(){},translate(){}})},PostPlusPreferences:{closeNavigation(){}},FileReader:class {readAsDataURL(file){this.result="data:application/octet-stream;base64,"+Buffer.from(file.data).toString("base64");Promise.resolve().then(()=>this.onload());}}};
  vm.createContext(sandbox);vm.runInContext(fs.readFileSync(path.join(__dirname,"../web/app.js"),"utf8"),sandbox);
  vm.runInContext('state.user={username:"writer@example.test",csrf:"csrf"};loadInbox=async()=>{};',sandbox);
  return {sandbox,id,run:source=>vm.runInContext(source,sandbox),events};
}
async function main(){
  const f=fixture();
  f.run('state.selected="original";state.previews.set("original",{subject:"Thread",from:"Person <source@example.test>",reply_to:"Reply <reply@example.test>",to:"writer@example.test, other@example.test",cc:"copy@example.test",date:"Today",text:"Quoted body",attachments:[{index:1,filename:"<img src=x>.bin",size:4,content_type:"application/octet-stream"}]});beginResponse("reply-all");');
  assert.equal(f.id("compose-subject").value,"Re: Thread");assert.equal(f.id("compose-to").value,"reply@example.test, other@example.test, copy@example.test");assert.match(f.id("compose-text").value,/> Quoted body/);
  let payload=f.run("composePayload()");assert.equal(payload.reply_to_id,"original");assert.equal(payload.attachments.length,0,"Replies do not attach original files automatically");
  f.run('resetCompose();beginResponse("forward");');payload=f.run("composePayload()");assert.equal(payload.attachments[0].message_id,"original");assert.equal(payload.attachments[0].index,1);assert.match(f.id("compose-text").value,/Forwarded message/);assert.match(f.id("compose-attachments").textContent,/<img src=x>/,"Untrusted names use literal text");
  f.run('renderAttachments("id /?",[{index:0,filename:"<script>file</script>",size:4}]);');const link=f.id("message-attachments").children[0];assert.equal(link.href,"/api/messages/id%20%2F%3F?attachment=0");assert.match(link.textContent,/<script>file<\/script>/);
  f.run('resetCompose();state.selected="draft";beginCompose({to:"Target <target@example.test>",cc:"copy@example.test",bcc:"hidden@example.test",subject:"Draft",text:"plain",html:"<p>rich</p><script>discard()</script>",attachments:[{index:1,filename:"last.bin",size:4}],in_reply_to:"<source@example.test>"});');
  assert.equal(f.id("compose-to").value,"target@example.test");assert.equal(f.id("compose-copy-fields").open,true);assert.equal(f.id("compose-format").checked,true);assert.equal(f.id("compose-rich").hidden,false);assert.doesNotMatch(f.id("compose-rich").innerHTML,/script/);
  payload=f.run("composePayload()");assert.equal(payload.html,"<p>rich</p>");assert.equal(payload.bcc[0],"hidden@example.test");assert.equal(payload.attachments[0].index,1);assert.equal(payload.in_reply_to,"<source@example.test>");
  let captured;f.sandbox.capture=(route,options)=>{captured={route,options};return {ok:true,id:"saved-draft"};};f.run('api=async(route,options)=>capture(route,options);');
  await f.id("draft-save").fire("click");assert.equal(captured.route,"/api/drafts");assert.equal(captured.options.body.attachments[0].index,1);
  payload=f.run("composePayload()");assert.equal(payload.attachments[0].message_id,"saved-draft");assert.equal(payload.attachments[0].index,0,"Saved draft references follow the new MIME part order");
  const remove=f.id("compose-attachments").children[0].children.at(-1);remove.fire("click");assert.equal(f.run("state.composeAttachments.length"),0);assert.equal(f.run("state.composeDirty"),true);
  f.id("compose-files").files=[{name:"data.bin",size:3,type:"",data:"abc"}];await f.id("compose-files").fire("change");payload=f.run("composePayload()");assert.equal(payload.attachments[0].data_base64,"YWJj");assert.equal(payload.attachments[0].content_type,"application/octet-stream");
  f.run('signedOut()');assert.equal(f.id("compose-attachments").children.length,0);assert.equal(f.id("compose-rich").innerHTML,"");assert.equal(f.run("state.composeAttachments.length"),0);
  f.sandbox.messageData={ok:true,folder:"Drafts",raw:"raw",message:{subject:"Search draft",text:"",html:"<p>Keep formatting</p>",to:"target@example.test",attachments:[{index:0,filename:"kept.bin",size:2}]}};
  f.run('state.user={username:"writer@example.test",csrf:"csrf"};state.view="INBOX";state.messages=[{id:"found-draft",folder:"Drafts",seen:true}];api=async()=>messageData;');
  await f.run('openMessage("found-draft")');assert.equal(f.id("draft-edit").hidden,false,"Global search uses the selected message folder for draft actions");assert.equal(f.run('state.previews.get("found-draft").html'),"<p>Keep formatting</p>");
  f.run('beginCompose(state.previews.get("found-draft"))');assert.equal(f.id("compose-format").checked,true);assert.equal(f.run('composePayload().attachments[0].message_id'),"found-draft");
  const html=fs.readFileSync(path.join(__dirname,"../web/index.html"),"utf8");for(const name of ["compose-files","compose-rich","compose-format","compose-cc","compose-bcc","message-reply","message-reply-all","message-forward","message-attachments"])assert.equal(html.split(`id="${name}"`).length-1,1,name);
  console.log("Composer UI checks passed: reply/forward, safe attachment links, rich drafts, Cc/Bcc, reordered draft references, uploads and logout cleanup.");
}
main().catch(error=>{console.error(error);process.exitCode=1;});
