"use strict";
// DNS drafts and diagnostics are independent of Save settings. The server
// chooses the saved domain, listener ports, public resolver and probe targets.
window.PostPlusAdminDns = (() => {
  const t = (...args) => PostPlusI18n.t(...args);
  const statuses = {unchecked:"Not checked",not_configured:"Pending configuration",matched:"Published value matches",published:"Published — verify the address",missing:"Record not found",mismatch:"Published value differs",error:"Lookup unavailable",skipped:"Optional — not configured",stale:"Changed — check again"};
  const labels = {a:"A · server IPv4",aaaa:"AAAA · server IPv6 (optional)","webmail-a":"A · Webmail IPv4","webmail-aaaa":"AAAA · Webmail IPv6 (optional)","admin-a":"A · administration IPv4","admin-aaaa":"AAAA · administration IPv6 (optional)","shared-webmail-a":"A · shared Webmail IPv4","shared-webmail-aaaa":"AAAA · shared Webmail IPv6 (optional)",mx:"MX · incoming mail",spf:"TXT · SPF",dkim:"DKIM · outgoing signing",dmarc:"TXT · DMARC"};
  const fields = [["ipv4","Server public IPv4 address"],["ipv6","Server public IPv6 address (optional)"],["spf","SPF TXT value"],["dkim_name","Full DKIM record name"],["dkim_type","DKIM record type"],["dkim_value","DKIM public TXT value or CNAME target"],["dmarc","DMARC TXT policy"]];
  function create(root,{request,prefix="admin-dns",onReport,onChanged,onBusy,draft=false}={}) {
    let disposed=false,revision=0,busy=false,report=null,error=null,checked=false,stale=false,spfEdited=false;
    const controls=new Map();
    function node(tag,text,className){const item=document.createElement(tag);if(text){item.dataset.i18n=text;item.textContent=t(text);}if(className)item.className=className;return item;}
    root.replaceChildren();
    const intro=node("p",draft?"Publish the records below at your DNS provider, then verify this domain. Your existing mail server and signing key are reused.":"DNS uses the saved server settings. Publish these records at your DNS provider, then test them here without saving or restarting PostPlus.","field-hint"),summary=node("p",null,"dns-prerequisite"),edit=node("details",null,"dns-technical"),grid=node("div",null,"settings-grid admin-dns-fields");
    const domainLabel=node("label","Mail domain"),domainSelect=node("select");domainSelect.id=`${prefix}-domain`;domainSelect.setAttribute("aria-label",t("Mail domain"));domainLabel.append(domainSelect);domainLabel.hidden=true;
    domainSelect.addEventListener("change",()=>load(false));
    edit.append(node("summary","Expected DNS values (optional)"),node("p","Enter your actual public IPs to compare them with DNS and prepare an exact SPF policy. For a relay or an existing policy, enter the values you want to keep. These fields are only used for this check.","field-hint"),grid);
    for(const [name,label] of fields){
      const wrap=node("div",null,"setting-field"+(["spf","dkim_value","dmarc"].includes(name)?" wide":"")),caption=node("label",label),input=node(name==="dkim_type"?"select":["spf","dkim_value","dmarc"].includes(name)?"textarea":"input");
      input.id=`${prefix}-${name}`;caption.htmlFor=input.id;input.autocomplete="off";input.spellcheck=false;input.maxLength=name==="dkim_name"?253:["ipv4","ipv6"].includes(name)?64:4096;
      if(name==="dkim_type"){for(const value of ["TXT","CNAME"]){const option=node("option");option.value=value;option.textContent=value;input.append(option);}input.value="TXT";}
      else if(input.tagName==="TEXTAREA")input.rows=name==="dkim_value"?4:2;else input.type="text";
      input.addEventListener(name==="dkim_type"?"change":"input",()=>{revision++;stale=checked;error=null;onChanged?.();if(name==="spf")spfEdited=true;if(["ipv4","ipv6"].includes(name)&&!spfEdited&&report?.outbound_mode==="direct"){const mechanisms=[controls.get("ipv4").value.trim()?"ip4:"+controls.get("ipv4").value.trim():"",controls.get("ipv6").value.trim()?"ip6:"+controls.get("ipv6").value.trim():""].filter(Boolean);controls.get("spf").value="v=spf1 "+(mechanisms.length?mechanisms.join(" "):"mx")+" -all";}render();});
      wrap.append(caption,input);grid.append(wrap);controls.set(name,input);
    }
    const actions=node("div",null,"dns-check-actions"),reload=node("button","Reload DNS recommendations","button secondary"),check=node("button","Test DNS and connectivity","button primary"),status=node("p",null,"field-hint"),failure=node("p",null,"form-error"),records=node("div",null,"dns-record-grid"),connections=node("section",null,"dns-connectivity");
    reload.type=check.type="button";reload.id=`${prefix}-reload`;check.id=`${prefix}-check`;status.id=`${prefix}-status`;status.setAttribute("role","status");status.setAttribute("aria-live","polite");failure.setAttribute("role","alert");actions.append(reload,check);
    connections.append(node("h3","Public service connectivity"));
    const connectionRows=node("div",null,"mail-client-grid");connections.append(connectionRows,node("p","Connection tests run from this server to its published public addresses. A failure may be caused by firewall or NAT loopback rules; a success does not prove that another network can reach the server. These tests do not validate TLS certificates or mail delivery.","field-hint"));
    root.append(intro,domainLabel,summary,edit,actions,status,failure,records,connections,node("p","Set PTR at your VPS or IP provider. Keep A/AAAA and MX in DNS-only mode. Merge authorized senders into one SPF record and publish only one DMARC policy. Existing matching records remain listed here.","field-hint"));
    function copy(parent,label,value){const wrap=node("div",null,"dns-copy"),caption=node("span",label),input=node(value.length>160?"textarea":"input");if(input.tagName==="INPUT")input.type="text";else input.rows=2;input.value=value;input.readOnly=true;input.spellcheck=false;input.setAttribute("aria-label",t(label));input.addEventListener("click",()=>input.select());wrap.append(caption,input);parent.append(wrap);}
    function expected(){return {domain:domainSelect.value,...Object.fromEntries([...controls].map(([name,input])=>[name,input.value.trim()]))};}
    function render(){
      if(disposed)return;
      domainSelect.disabled=busy;reload.disabled=busy;check.disabled=busy||!report||domainSelect.value!==report.domain;check.textContent=t(busy?"Checking DNS and connectivity…":"Test DNS and connectivity");for(const input of controls.values())input.disabled=busy;
      summary.textContent=report?t("Mail stays at @{domain}; the server address is {hostname}.",{domain:report.domain,hostname:report.hostname}):"";
      status.textContent=busy?t(report?"Checking public records and configured service ports…":"Loading DNS recommendations…"):stale?t("Expected values changed. Run the test again."):checked?t("DNS and connectivity checked at {time}.",{time:report.checked_at}):t("All recommended records are listed, including records already published. Enter expected values or run a test to see current public DNS.");
      failure.hidden=!error;failure.textContent=error?(error.message||PostPlusI18n.error(error.data||error)):"";records.replaceChildren();
      for(const record of report?.records||[]){
        const card=node("article",null,"dns-record"),heading=node("h4"),badge=node("span",null,"dns-record-status"),state=stale?"stale":record.status;
        card.dataset.record=record.id;card.dataset.status=state;heading.append(node("span",labels[record.id]||(record.type==="PTR"?"PTR · reverse DNS":"SRV · mail app discovery")),badge);badge.textContent=t(statuses[state]||"Not checked");card.append(heading);
        copy(card,"Record type",record.type);copy(card,"Name / host",record.type==="PTR"?t("Set at your IP provider"):record.host||record.name||"@");if(record.name)copy(card,"Full DNS name",record.name);
        if(record.value)copy(card,"Value / content",record.value);else card.append(node("p",record.id==="dkim"?"Generate or load the public signing key under DKIM below, or enter your relay's public record above.":"Enter the expected record value to check it.","field-hint"));
        if(record.type==="MX")card.append(node("p","MX value starts with priority 10, followed by the mail server hostname. Use separate fields if your DNS provider asks for them.","field-hint"));
        if(record.type==="SRV")card.append(node("p","SRV value order is priority, weight, port, target. If your DNS provider uses separate fields, enter 0, 1, the port, and the mail hostname. A successful DNS lookup does not test the listener or certificate.","field-hint"));
        if(checked){const observed=node("p",null,"field-hint");observed.textContent=record.observed?.length?t("Published: {values}",{values:record.observed.join(" · ")}):t(record.status==="error"?"Lookup failed; the published value is unknown.":"No records returned");card.append(observed);if(record.code==="dns_mx_alias")card.append(node("p","The mail hostname is a CNAME alias. An MX target needs direct A/AAAA records.","field-hint"));if(record.code==="dns_private_address")card.append(node("p","The mail hostname resolves to a private or reserved address. Public connectivity was not tested for that address.","field-hint"));}
        records.append(card);
      }
      connections.hidden=!checked;connectionRows.replaceChildren();
      for(const connection of report?.connectivity||[]){const card=node("article",null,"mail-client-card"),heading=node("h4");heading.textContent=`${connection.service.toUpperCase()} · ${connection.port}`;card.append(heading);const detail=node("p",null,"field-hint");detail.textContent=t({reachable:"TCP connection succeeded",unreachable:"TCP connection failed",timeout:"Test time limit reached",not_checked:"Not tested — no public address available"}[connection.status]||"Not checked");card.append(detail);for(const item of connection.addresses||[])copy(card,item.reachable?"Reachable address":"Unreachable address",item.address);connectionRows.append(card);}
    }
    function validate(data){if(!data?.ok||typeof data.domain!=="string"||typeof data.hostname!=="string"||!data.expected||!Array.isArray(data.records)||data.records.some(record=>!record||typeof record.id!=="string"||typeof record.name!=="string"||typeof record.type!=="string"||typeof record.value!=="string"||!statuses[record.status]||!Array.isArray(record.observed)||record.observed.some(value=>typeof value!=="string")))throw new Error(t("The server returned an unreadable response."));return data;}
    async function load(test){
      if(disposed||busy)return;const current=++revision;busy=true;error=null;onBusy?.(true);render();
      try{const data=validate(await request(test?"/check":domainSelect.value?"?domain="+encodeURIComponent(domainSelect.value):"",test?{method:"POST",body:expected()}:{method:"GET"}));if(disposed||current!==revision)return;report=data;checked=test;stale=false;domainSelect.replaceChildren();for(const value of data.domains||[data.domain]){const option=node("option");option.value=value;option.textContent=value;domainSelect.append(option);}domainSelect.value=data.domain;domainLabel.hidden=draft||(data.domains||[data.domain]).length<2;if(!test){spfEdited=false;for(const [name,input] of controls)input.value=typeof data.expected[name]==="string"?data.expected[name]:"";}onReport?.(data,{checked:test});}
      catch(problem){if(!disposed&&current===revision)error=problem;}
      finally{if(!disposed){busy=false;onBusy?.(false);render();}}
    }
    check.addEventListener("click",()=>load(true));reload.addEventListener("click",()=>load(false));render();load(false);
    return {reload:()=>load(false),translate(){PostPlusI18n.apply(root);render();},dispose(){disposed=true;revision++;root.replaceChildren();}};
  }
  return {create};
})();
