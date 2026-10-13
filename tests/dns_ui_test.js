"use strict";
// Behavioral checks use the production DNS component with deferred API replies.
// No live DNS query, setup submission, or certificate issuance is performed.
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
const root=path.resolve(__dirname,"..");
const descendants=element=>element.children.flatMap(child=>[child,...descendants(child)]);
class Element {
  constructor(tag="div"){this.tagName=tag.toUpperCase();this.children=[];this.dataset={};this.attributes={};this.events=new Map();this.value="";this.hidden=false;this.disabled=false;this.textContent="";}
  get textContent(){return this.text+this.children.map(child=>child.textContent).join("");}
  set textContent(value){this.text=String(value);this.children=[];}
  append(...items){for(const item of items){if(item.parentElement)item.parentElement.children=item.parentElement.children.filter(child=>child!==item);item.parentElement=this;this.children.push(item);}}
  prepend(...items){for(const item of items)item.parentElement=this;this.children.unshift(...items);}
  replaceChildren(...items){this.children=[];this.append(...items);}
  setAttribute(name,value){this.attributes[name]=value;}
  getAttribute(name){return this.attributes[name];}
  addEventListener(name,listener){if(!this.events.has(name))this.events.set(name,[]);this.events.get(name).push(listener);}
  async fire(name){for(const listener of this.events.get(name)||[])await listener({target:this});}
  select(){this.selected=true;}
  querySelectorAll(selector){const all=descendants(this);if(selector==="[data-i18n]")return all.filter(item=>item.dataset.i18n);const match=/^\[data-i18n-(.+)\]$/.exec(selector);return match?all.filter(item=>item.attributes[`data-i18n-${match[1]}`]):[];}
}
function fixture({domain="example.com",hostname="",relay="",mode,selector,request,generateDkim}={}){
  const container=new Element(),inputs={domain:new Element("input"),hostname:new Element("input"),relayHost:new Element("input"),smtpPort:new Element("input")},requests=[],callbacks=new Map(),domains=[];
  inputs.domain.value=domain;inputs.hostname.value=hostname;inputs.relayHost.value=relay;inputs.smtpPort.value="2525";
  const sandbox={window:{},URL,document:{createElement:tag=>new Element(tag),documentElement:{lang:"en"},querySelectorAll:()=>[],dispatchEvent(){},addEventListener:(name,listener)=>callbacks.set(name,listener)},localStorage:{getItem:()=>null,setItem(){}},CustomEvent:class{constructor(type){this.type=type;}}};
  vm.runInNewContext(fs.readFileSync(path.join(root,"web/i18n.js"),"utf8"),sandbox);sandbox.PostPlusI18n=sandbox.window.PostPlusI18n;
  vm.runInNewContext(fs.readFileSync(path.join(root,"web/dns.js"),"utf8"),sandbox);
  const api=sandbox.window.PostPlusDns,relaySettings=new Element("details");relaySettings.id="setup-relay-config";
  const keyRequests=[];
  const component=api.create(container,{inputs,relaySettings,initialMode:mode,initialSelector:selector,onHostnameChange:value=>domains.push(value),generateDkim:body=>{keyRequests.push(JSON.parse(JSON.stringify(body)));return generateDkim?.(body);},request:body=>{requests.push(JSON.parse(JSON.stringify(body)));return request?.(body);}});
  const id=name=>descendants(container).find(item=>item.id===`setup-dns-${name}`),card=name=>descendants(container).find(item=>item.dataset.record===name),copy=(name,label)=>descendants(card(name)).filter(item=>item.readOnly).find(item=>item.attributes["aria-label"]===label);
  async function edit(name,value){id(name).value=value;await id(name).fire(id(name).tagName==="SELECT"?"change":"input");}
  return {container,inputs,requests,keyRequests,domains,component,api,i18n:sandbox.PostPlusI18n,id,card,copy,edit,relaySettings};
}
function result(overrides={}){
  return {ok:true,resolver:"Cloudflare public DNS (1.1.1.1)",checked_at:"2026-10-12T12:00:00Z",records:["a","aaaa","mx","spf","dkim","dmarc"].map(id=>({id,status:id==="aaaa"?"not_configured":"matched",observed:id==="aaaa"?[]:[id==="a"?"8.8.8.8":"observed "+id],...(overrides[id]||{})}))};
}
async function main(){
  const f=fixture();
  assert.equal(f.inputs.hostname.value,"mail.example.com","Mail server uses a subdomain; root website remains independent");
  assert.deepEqual(f.domains,["mail.example.com"]);
  const mailDomain=fixture({domain:"mail.example.com"});assert.equal(mailDomain.inputs.hostname.value,"mail.example.com","Do not duplicate an existing mail hostname prefix");assert.equal(mailDomain.copy("mx","Value / content").value,"mail.example.com.");
  assert.equal(f.copy("mx","Name / host").value,"@");
  assert.equal(f.copy("mx","Value / content").value,"mail.example.com.");
  assert.equal(f.card("a").dataset.status,"not_configured","Never fabricate an IP");
  assert.equal(f.card("spf").dataset.status,"not_configured");
  assert.equal(f.card("dkim").dataset.status,"not_configured");
  assert.equal(f.copy("dkim","Value / content"),undefined,"Placeholder selector/key cannot become publishable records");
  assert.equal(f.id("spf").disabled,true,"Provider authentication waits until a relay is configured");
  assert.equal(f.id("dkim-name").value,"");assert.equal(f.id("dkim-value").value,"");
  assert.ok(f.id("spf").placeholder.startsWith("v=spf1"));
  await f.edit("ipv4","8.8.8.8");
  assert.equal(f.copy("a","Name / host").value,"mail");
  assert.equal(f.copy("a","Full DNS name").value,"mail.example.com");
  assert.equal(f.copy("a","Value / content").value,"8.8.8.8");
  await f.copy("a","Value / content").fire("click");assert.equal(f.copy("a","Value / content").selected,true);
  f.inputs.domain.value="team.example.com";await f.inputs.domain.fire("input");
  assert.equal(f.inputs.hostname.value,"mail.team.example.com");
  assert.equal(f.copy("a","Name / host").value,"mail");
  assert.ok(descendants(f.container).some(item=>item.textContent.includes("For a parent zone")));
  f.inputs.hostname.value="smtp.other.com";await f.inputs.hostname.fire("input");
  f.inputs.domain.value="new.example.com";await f.inputs.domain.fire("input");
  assert.equal(f.inputs.hostname.value,"smtp.other.com","Manual hostname survives later domain changes");
  assert.equal(f.copy("a","Name / host").value,"smtp.other.com.","Cross-zone hostname remains fully qualified");
  assert.equal(f.copy("mx","Value / content").value,"smtp.other.com.");
  assert.equal(f.requests.length,0,"Editing and preparing records never triggers a network check");
  assert.equal(f.id("check").textContent,"Check public DNS");
  assert.equal(f.card("mx").dataset.status,"unchecked");
  assert.equal(f.copy("dmarc","Value / content").value,"v=DMARC1; p=none");
  assert.ok(descendants(f.container).some(item=>item.textContent.includes("TCP ports, PTR, DKIM signing")));
  for(const value of ["127.0.0.1","192.168.1.1","100.64.1.1","203.0.113.10","999.0.0.1"]){await f.edit("ipv4",value);assert.equal(f.id("check").disabled,true);assert.equal(f.copy("a","Value / content"),undefined);}
  await f.edit("ipv4","192.0.1.2");assert.equal(f.id("check").disabled,false);
  for(const value of ["::1","::2","::7f00:1","2001:db8::1","3fff::1","fd00::1","2001:zz::1"]){await f.edit("ipv6",value);assert.equal(f.id("check").disabled,true);assert.equal(f.copy("aaaa","Value / content"),undefined);}
  await f.edit("ipv6","3fff:1000::1");assert.equal(f.id("check").disabled,false);
  await f.edit("ipv6","");
  f.inputs.relayHost.value="smtp.provider.com";await f.inputs.relayHost.fire("input");
  await f.edit("outbound-mode","relay");
  assert.equal(f.id("spf").disabled,false);
  await f.edit("spf","v=spf1 include:spf.provider.com -all");
  await f.edit("dkim-name","selector._domainkey");await f.edit("dkim-value",'"v=DKIM1; k=rsa; " "p=YWJjMTIz"');
  assert.equal(f.component.read().dkim_name,"selector._domainkey.new.example.com");
  assert.equal(f.component.read().dkim_value,"v=DKIM1; k=rsa; p=YWJjMTIz");
  assert.equal(f.copy("spf","Value / content").value,"v=spf1 include:spf.provider.com -all");
  assert.equal(f.copy("dkim","Value / content").value,"v=DKIM1; k=rsa; p=YWJjMTIz");
  await f.edit("dkim-name","selector._domainkey.new.example.com.");assert.equal(f.component.read().dkim_name,"selector._domainkey.new.example.com");
  await f.edit("dkim-name","selector._domainkey.wrong.com");assert.equal(f.id("check").disabled,true);assert.equal(f.copy("dkim","Value / content"),undefined);
  await f.edit("dkim-name","selector");await f.edit("dkim-value","k=rsa; p=YWJjMTIz");assert.equal(f.id("check").disabled,false,"DKIM v tag is optional");
  await f.edit("dkim-value","k=rsa; p = YWJj MTIz");assert.equal(f.id("check").disabled,false,"DKIM tags and public-key folding accept legal whitespace");
  await f.edit("dkim-value","v = DKIM2; p=YWJjMTIz");assert.equal(f.id("check").disabled,true);
  await f.edit("dkim-value","p=YWJjMTIz; p=YWJjMTIz");assert.equal(f.id("check").disabled,true,"Reject duplicate public-key tags");
  await f.edit("dkim-value","v=DKIM2; p=YWJjMTIz");assert.equal(f.id("check").disabled,true);
  await f.edit("dkim-value","v=DKIM1; p=");assert.equal(f.id("check").disabled,true,"Revoked key cannot be a usable public key");
  await f.edit("dkim-value","-----BEGIN PRIVATE KEY-----");assert.equal(f.id("check").disabled,true);
  await f.edit("dkim-type","CNAME");await f.edit("dkim-value","selector.keys.provider.com.");assert.equal(f.id("check").disabled,false);
  assert.equal(f.copy("dkim","Value / content").value,"selector.keys.provider.com.");
  assert.equal(f.component.read().dkim_type,"CNAME");
  assert.equal(f.copy("dkim","Name / host").value,"selector._domainkey");
  assert.equal(f.copy("dkim","Record type").value,"CNAME");
  await f.edit("dkim-value","selector1-new-example-com._domainkey.tenant.onmicrosoft.com");assert.equal(f.id("check").disabled,false,"Microsoft 365 CNAME target may contain _domainkey");
  assert.equal(f.copy("dkim","Value / content").value,"selector1-new-example-com._domainkey.tenant.onmicrosoft.com");
  assert.equal(f.api.dkimName("a".repeat(63)+"."+"b".repeat(63)+"."+"c".repeat(63)+"._domainkey","d".repeat(63)+".new.example.com"),"","Normalized DKIM name must fit the full DNS-name limit");
  await f.edit("dmarc","v=DMARC1 ; rua=mailto:reports@new.example.com; p=none");assert.equal(f.id("check").disabled,false,"Existing provider policies can put p after other tags");
  assert.equal(f.copy("dmarc","Value / content").value,"v=DMARC1 ; rua=mailto:reports@new.example.com; p=none");
  await f.edit("dmarc","v=DMARC1; p=none; p=reject");assert.equal(f.id("check").disabled,true,"Do not prepare ambiguous duplicate policy tags");
  await f.edit("dmarc","v=DMARC1; p=none");
  f.inputs.relayHost.value="";await f.inputs.relayHost.fire("input");assert.equal(f.component.read().spf,"");assert.equal(f.component.read().dkim_value,"");assert.equal(f.card("spf").dataset.status,"not_configured");
  assert.equal(f.id("spf").value,"v=spf1 include:spf.provider.com -all","Temporarily removing relay preserves draft values without declaring them configured");
  const local=fixture({domain:"localhost"});assert.equal(local.inputs.hostname.value,"");assert.equal(local.id("check").disabled,true);assert.ok(local.id("prerequisite").textContent.includes("Local mail needs no public DNS"));

  let resolveFirst,resolveSecond;
  const pending=[];
  const live=fixture({relay:"smtp.provider.com",request:()=>new Promise(resolve=>pending.push(resolve))});
  await live.edit("ipv4","8.8.8.8");await live.edit("spf","v=spf1 include:spf.provider.com -all");await live.edit("dkim-name","selector");await live.edit("dkim-value","v=DKIM1; p=YWJjMTIz");
  const first=live.id("check").fire("click");assert.equal(live.id("check").disabled,true);assert.equal(live.id("check").textContent,"Checking public DNS…");
  assert.deepEqual(live.requests[0],{domain:"example.com",hostname:"mail.example.com",ipv4:"8.8.8.8",ipv6:"",spf:"v=spf1 include:spf.provider.com -all",dkim_name:"selector._domainkey.example.com",dkim_type:"TXT",dkim_value:"v=DKIM1; p=YWJjMTIz",dmarc:"v=DMARC1; p=none"});
  await live.edit("ipv4","1.1.1.1");assert.equal(live.id("check").disabled,true,"Wait for server's active request before starting a second query");assert.match(live.id("check-status").textContent,/results will be discarded/);
  await live.id("check").fire("click");assert.equal(live.requests.length,1);
  pending[0](result());await first;assert.equal(live.card("a").dataset.status,"stale","Input edits invalidate the request before its reply arrives");assert.equal(live.id("check").disabled,false);
  const second=live.id("check").fire("click");pending[1](result({a:{status:"mismatch",observed:["8.8.8.8"],code:"dns_mx_alias"},aaaa:{status:"mismatch",observed:["2001:db8::99"],code:"dns_unexpected_record"},spf:{status:"missing",observed:[],code:"dns_missing"},dkim:{status:"error",observed:[],code:"dns_truncated"}}));await second;
  assert.equal(live.card("a").dataset.status,"mismatch");assert.equal(live.card("aaaa").dataset.status,"mismatch","Existing wrong AAAA remains visible when optional input is blank");
  assert.equal(live.card("spf").dataset.status,"missing");assert.equal(live.card("dkim").dataset.status,"error");assert.equal(live.card("mx").dataset.status,"matched");
  assert.match(live.id("check-status").textContent,/2026-10-12T12:00:00Z.*Cloudflare/);
  assert.ok(descendants(live.card("a")).some(item=>item.textContent.includes("CNAME alias")));
  assert.ok(descendants(live.card("dkim")).some(item=>item.textContent.includes("answer was too large")));
  assert.ok(descendants(live.card("dkim")).some(item=>item.textContent.includes("Unknown — lookup failed")));
  assert.ok(!descendants(live.card("dkim")).some(item=>item.textContent.includes("No records returned")));
  live.i18n.setLanguage("zh-CN");live.component.translate();assert.match(live.card("mx").children[0].textContent,/MX/);assert.ok(descendants(live.card("mx")).some(item=>item.textContent==="DNS 内容匹配"));assert.match(live.id("check-status").textContent,/检查时间/);
  live.inputs.hostname.value="smtp.example.com";await live.inputs.hostname.fire("input");assert.equal(live.card("mx").dataset.status,"stale");assert.ok(!descendants(live.container).some(item=>item.textContent==="DNS 内容匹配"));
  live.i18n.setLanguage("en");live.component.translate();
  const third=live.id("check").fire("click");live.component.dispose();pending[2](result());await third;assert.equal(live.card("mx").dataset.status,"stale","Disposed UI cannot receive results");
  const broken=fixture({request:async()=>{throw new Error("Network failed");}});await broken.edit("ipv4","8.8.8.8");await broken.id("check").fire("click");assert.equal(broken.card("a").dataset.status,"unchecked");assert.ok(descendants(broken.container).some(item=>item.textContent.includes("DNS lookup could not be completed")));
  const unknownIpv6=fixture({request:async()=>result({aaaa:{status:"error",code:"dns_timeout",observed:[]}})});await unknownIpv6.edit("ipv4","8.8.8.8");await unknownIpv6.id("check").fire("click");assert.equal(unknownIpv6.card("aaaa").dataset.status,"error","A DNS timeout cannot prove no stale AAAA exists");assert.ok(descendants(unknownIpv6.card("aaaa")).some(item=>item.textContent.includes("result is unknown")));
  const skipped=fixture({request:async()=>result({spf:{status:"not_configured",code:"dns_not_configured",observed:[]},dkim:{status:"not_configured",code:"dns_not_configured",observed:[]},aaaa:{status:"mismatch",code:"dns_mx_alias",observed:[]}})});await skipped.edit("ipv4","8.8.8.8");await skipped.id("check").fire("click");assert.equal(skipped.card("aaaa").dataset.status,"mismatch","CNAME alias mismatch is surfaced even with no optional IPv6 expected value");assert.ok(descendants(skipped.card("spf")).some(item=>item.textContent.startsWith("Not queried")));assert.ok(!descendants(skipped.card("spf")).some(item=>item.textContent.includes("No records returned")));
  const occupied=fixture({request:async()=>{throw {code:"setup_busy"};}});await occupied.edit("ipv4","8.8.8.8");await occupied.id("check").fire("click");assert.ok(descendants(occupied.container).some(item=>item.textContent.includes("Another setup operation is still running")));
  const keyResponse=({domain,selector})=>({ok:true,domain,selector,name:selector+"._domainkey."+domain,type:"TXT",value:"v=DKIM1; k=rsa; h=sha256; p="+"A".repeat(392),fingerprint:"SHA256:public-key-fingerprint"});
  const direct=fixture({mode:"direct",hostname:"smtp.example.com",generateDkim:async body=>keyResponse(body),request:async()=>result()});
  assert.equal(direct.inputs.hostname.value,"smtp.example.com","Saved mail hostname is preserved on create");
  assert.equal(direct.component.directReady(),false,"Direct delivery cannot save a placeholder key");
  assert.equal(direct.component.read().spf,"");assert.equal(direct.component.read().dkim_value,"");
  assert.equal(direct.relaySettings.hidden,true,"Direct mode does not require an SMTP relay");
  assert.ok(descendants(direct.container).some(item=>item.textContent.includes("outbound TCP 25")));
  const ptr=descendants(direct.container).find(item=>item.readOnly&&item.attributes["aria-label"]==="Expected PTR hostname");assert.equal(ptr.value,"smtp.example.com");
  await direct.edit("ipv4","203.0.113.10");assert.equal(direct.component.read().spf,"","Documentation addresses never become SPF authorization");
  await direct.edit("ipv4","8.8.8.8");await direct.edit("ipv6","2606:4700:4700::1111");
  assert.equal(direct.copy("spf","Value / content").value,"v=spf1 ip4:8.8.8.8 ip6:2606:4700:4700::1111 -all");
  await direct.id("generate-dkim").fire("click");assert.equal(direct.component.directReady(),true);
  assert.deepEqual(direct.keyRequests,[{domain:"example.com",selector:"postplus"}]);
  assert.deepEqual(JSON.parse(JSON.stringify(direct.component.settings())),{outbound_mode:"direct",dkim_selector:"postplus",dkim_fingerprint:"SHA256:public-key-fingerprint"});
  assert.equal(direct.copy("dkim","Full DNS name").value,"postplus._domainkey.example.com");assert.equal(direct.copy("dkim","Value / content").readOnly,true);
  assert.equal(direct.copy("dkim","Record type").value,"TXT","DNS providers need the explicit record type");
  await direct.id("check").fire("click");assert.equal(direct.requests[0].dkim_value,keyResponse({domain:"example.com",selector:"postplus"}).value);assert.equal(direct.requests[0].dkim_type,"TXT");
  await direct.id("generate-dkim").fire("click");assert.equal(direct.component.directReady(),true,"Existing key may be loaded again");
  await direct.edit("selector","new");assert.equal(direct.component.directReady(),false);assert.equal(direct.component.read().dkim_value,"");
  await direct.id("generate-dkim").fire("click");assert.equal(direct.component.read().dkim_name,"new._domainkey.example.com");
  direct.inputs.domain.value="new.example.com";await direct.inputs.domain.fire("input");assert.equal(direct.component.directReady(),false,"Domain edits invalidate loaded key");
  await direct.edit("outbound-mode","disabled");assert.equal(direct.component.read().spf,"");assert.equal(direct.component.read().dkim_value,"");assert.equal(direct.component.directReady(),true);
  direct.component.suggestMode("direct");assert.equal(direct.component.settings().outbound_mode,"disabled","Explicit mode choice survives automatic suggestions");
  const auto=fixture();auto.component.suggestMode("direct");assert.equal(auto.component.settings().outbound_mode,"direct");auto.component.suggestMode("disabled");assert.equal(auto.component.settings().outbound_mode,"disabled");
  const replies=[];const racing=fixture({mode:"direct",generateDkim:()=>new Promise(resolve=>replies.push(resolve))});
  const loading=racing.id("generate-dkim").fire("click");await racing.edit("selector","updated");assert.equal(racing.id("generate-dkim").disabled,true,"Only one key operation runs at a time");
  replies[0](keyResponse({domain:"example.com",selector:"postplus"}));await loading;assert.equal(racing.component.directReady(),false);assert.equal(racing.component.read().dkim_value,"");
  const loading2=racing.id("generate-dkim").fire("click");racing.inputs.domain.value="other.example.com";await racing.inputs.domain.fire("input");replies[1](keyResponse({domain:"example.com",selector:"updated"}));await loading2;assert.equal(racing.component.directReady(),false,"Stale domain response discarded");
  for(const mutate of [data=>({...data,domain:"wrong.example.com"}),data=>({...data,value:"-----BEGIN PRIVATE KEY-----"}),data=>({...data,private_key:"secret"}),data=>({...data,type:"CNAME"})]){
    const malformed=fixture({mode:"direct",generateDkim:async body=>mutate(keyResponse(body))});await malformed.id("generate-dkim").fire("click");assert.equal(malformed.component.directReady(),false);assert.equal(malformed.copy("dkim","Value / content"),undefined);assert.ok(descendants(malformed.container).some(item=>item.textContent.includes("Cannot generate or load")));
  }
  // Every production-generated UI string has a Chinese translation.
  for(const item of descendants(f.container))if(item.dataset.i18n){const en=item.dataset.i18n;f.i18n.setLanguage("zh-CN");assert.notEqual(f.i18n.t(en),en,`Missing translation: ${en}`);}f.i18n.setLanguage("en");
  const html=fs.readFileSync(path.join(root,"web/setup.html"),"utf8"),setup=fs.readFileSync(path.join(root,"web/setup.js"),"utf8");
  assert.match(html,/src="\/dns\.js"/);assert.match(html,/id="setup-hostname"/);assert.match(html,/value="existing"/);assert.match(html,/value="http01"/);
  assert.match(html,/This method does not require public port 80/);
  assert.match(setup,/\/api\/setup\/dns\/check/);assert.doesNotMatch(fs.readFileSync(path.join(root,"web/dns.js"),"utf8"),/TCP port 80|inbound TCP 80|public TCP 80/);
  console.log("DNS UI checks passed: independent mail hostname, provider records, TXT/CNAME, public address validation, real API contract, record statuses, unexpected AAAA, stale-response races, language switching, and certificate-method separation.");
}
main().catch(error=>{console.error(error);process.exitCode=1;});
