"use strict";
// DNS guidance is a draft, separate from persisted server settings and CA issuance.
window.PostPlusDns = (() => {
  const t = (...args) => PostPlusI18n.t(...args);
  const publicDomain = value => typeof value === "string" && value.length <= 253 && value.includes(".") && !/^\d+(?:\.\d+){3}$/.test(value) && !/(?:^|\.)(?:localhost|local|test|invalid|example)$/.test(value) && value.split(".").every(label => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
  const publicDnsTarget = value => typeof value === "string" && value.length <= 253 && value.includes(".") && !/^\d+(?:\.\d+){3}$/.test(value) && !/(?:^|\.)(?:localhost|local|test|invalid|example)$/i.test(value) && value.split(".").every(label => label.length <= 63 && /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/i.test(label));
  function publicIpv4(value) {
    if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || !value.split(".").every(part => Number(part) <= 255 && (part === "0" || !part.startsWith("0")))) return false;
    const [a,b,c] = value.split(".").map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)))) || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113));
  }
  function publicIpv6(value) {
    try {
      const normalized = new URL("http://[" + value + "]/").hostname.slice(1,-1), parts = normalized.split(":");
      return /^[0-9a-f:.]+$/i.test(value) && /^[23]/.test(normalized) && !normalized.startsWith("2001:db8:") && !(parts[0] === "3fff" && (!parts[1] || parseInt(parts[1],16) < 0x1000));
    } catch { return false; }
  }
  function dkimName(value, domain) {
    const name = value.trim().toLowerCase().replace(/\.$/, "");
    if (!name || !publicDomain(domain)) return "";
    const full = name.endsWith("._domainkey." + domain) ? name : name.endsWith("._domainkey") ? name + "." + domain : name.includes(".") ? name : name + "._domainkey." + domain;
    const selector = full.slice(0, -("._domainkey." + domain).length);
    return full.length<=253 && full.endsWith("._domainkey." + domain) && selector && selector.split(".").every(label => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) ? full : "";
  }
  function txtValue(value) {
    const raw = value.trim().replace(/\r?\n/g," ");
    if (!raw.startsWith('"')) return raw;
    // DNS consoles sometimes supply quoted, split TXT chunks. Preserve their bytes.
    const chunks = [...raw.matchAll(/"([^"\\]*)"/g)];
    return chunks.length && raw.replace(/"[^"\\]*"/g, "").trim() === "" ? chunks.map(match => match[1]).join("") : raw;
  }
  function create(root, {inputs, relaySettings, request, generateDkim, onHostnameChange, initialMode, initialSelector="postplus", prefix="setup-dns"}) {
    let version = 0, result = null, errorKey = "", busy = false, disposed = false, stale = false, hostnameEdited = publicDomain(String(inputs.hostname.value).trim().toLowerCase());
    let keyRevision=0, keyRecord=null, keyBusy=false, keyError="", keyProblem=null, modeEdited=false;
    const fields = {}, cards = new Map(), clean = input => String(input.value).trim(), domain = () => clean(inputs.domain).toLowerCase(), hostname = () => clean(inputs.hostname).toLowerCase();
    function node(tag, key, className) { const item = document.createElement(tag); if (key) {item.dataset.i18n = key;item.textContent = t(key);} if (className) item.className = className; return item; }
    function step(number, title, intro) {
      const section = node("section", null, "dns-step"), heading = node("h3"), badge = node("span",null,"dns-step-number");badge.textContent = String(number);
      heading.append(badge,node("span",title));section.append(heading,node("p",intro,"field-hint"));root.append(section);return section;
    }
    function field(parent, name, label, placeholder, {type="text",value="",multiline=false}={}) {
      const wrap = node("div",null,"dns-field"), caption = node("label",label), input = node(multiline ? "textarea" : "input");
      input.id = `${prefix}-${name}`;caption.htmlFor = input.id;input.placeholder = placeholder || "";input.value = value;input.autocomplete = "off";input.spellcheck = false;
      if (!multiline) input.type = type; else input.rows = 2;
      input.maxLength = multiline ? 4096 : name === "dkim-name" ? 253 : 512;
      wrap.append(caption,input);parent.append(wrap);fields[name] = input;input.addEventListener("input",invalidate);return input;
    }
    function technical(parent, title, paragraphs) { const details = node("details",null,"dns-technical");details.append(node("summary",title));for (const text of paragraphs) details.append(node("p",text,"field-hint"));parent.append(details);return details; }
    root.replaceChildren();
    const prerequisite = node("p",null,"dns-prerequisite");prerequisite.id = `${prefix}-prerequisite`;root.append(prerequisite);
    const incoming = step(2,"Receive mail","Add the server address first, then route your mail domain to it with MX.");
    const addressGrid = node("div",null,"grid-two");incoming.append(addressGrid);
    field(addressGrid,"ipv4","Server public IPv4 address","203.0.113.10");field(addressGrid,"ipv6","Server public IPv6 address (optional)","2001:db8::10");
    const addressError = node("p",null,"form-error");addressError.hidden = true;incoming.append(addressError);
    const receiveRecords = node("div",null,"dns-record-grid");incoming.append(receiveRecords);
    const smtp = node("p",null,"field-hint");incoming.append(smtp);
    const zone = node("p",null,"field-hint"), dnsNames = technical(incoming,"DNS names and network details",[
      "@ means your DNS zone root. Use the full name if your provider expects one; do not append the domain twice.",
      "A/AAAA must be in the zone that controls the mail server hostname. Use DNS-only mode, not an HTTP proxy. MX targets must have A/AAAA records and cannot be CNAME aliases.",
      "Leave IPv6 blank only if you have no public IPv6. Remove stale AAAA records at your DNS provider; an existing wrong AAAA can still break connections."]);dnsNames.append(zone);
    const outgoing = step(3,"Send to other domains","Choose how this server sends outgoing mail. Direct delivery includes built-in DKIM signing.");
    const modeWrap=node("div",null,"dns-mode-choice"),modeLabel=node("label","Outgoing delivery mode"),outboundMode=node("select");
    outboundMode.id=`${prefix}-outbound-mode`;outboundMode.name="outbound_mode";modeLabel.htmlFor=outboundMode.id;
    for(const [value,label] of [["direct","Direct delivery — recommended for your own server"],["relay","Send through an SMTP relay"],["disabled","Receive and local mail only"]]){const option=node("option",label);option.value=value;outboundMode.append(option);}
    outboundMode.value=["direct","relay","disabled"].includes(initialMode)?initialMode:clean(inputs.relayHost)?"relay":"disabled";
    modeWrap.append(modeLabel,outboundMode);outgoing.append(modeWrap);fields["outbound-mode"]=outboundMode;
    const directFields=node("div",null,"dns-direct-fields");outgoing.append(directFields);
    directFields.append(node("p","PostPlus connects directly to recipient MX servers and signs outgoing mail with its private DKIM key. Publish the public records below before sending.","dns-prerequisite"));
    const selector=field(directFields,"selector","DKIM selector","postplus",{value:initialSelector});selector.name="dkim_selector";selector.maxLength=63;
    const generate=node("button","Generate / load DKIM public record","button primary");generate.type="button";generate.id=`${prefix}-generate-dkim`;directFields.append(generate);
    const keyStatus=node("p",null,"field-hint"),keyFailure=node("p",null,"form-error");keyStatus.id=`${prefix}-dkim-status`;keyStatus.setAttribute("role","status");keyFailure.setAttribute("role","alert");directFields.append(keyStatus,keyFailure);
    const ptr=node("div",null,"dns-ptr");directFields.append(ptr);
    technical(directFields,"Direct delivery requirements",[
      "Your VPS provider must allow outbound TCP 25 to recipient mail servers. Inbound TCP 25 is also required to receive Internet mail.",
      "Set reverse DNS (PTR) for each outgoing public IP through your VPS or IP provider. Use the mail server hostname below and make its A/AAAA records point back to those IPs. PTR is not a TXT record in your domain's DNS console.",
      "Use the actual outbound public IPs in SPF. If this server uses NAT or another egress IP, enter that address. Merge any existing authorized senders into one SPF record.",
      "Successful DNS checks do not establish IP reputation or guarantee delivery. New IPs may need gradual sending and recipient-provider reputation checks."]);
    if (relaySettings) outgoing.append(relaySettings);
    const relayStatus = node("p",null,"dns-prerequisite");relayStatus.id = `${prefix}-relay-status`;outgoing.append(relayStatus);
    const authFields = node("div",null,"dns-auth-fields");outgoing.append(authFields);
    field(authFields,"spf","SPF TXT value for your outgoing relay","v=spf1 include:your-provider.example -all",{multiline:true});
    const dkimGrid = node("div",null,"grid-two");authFields.append(dkimGrid);
    field(dkimGrid,"dkim-name","DKIM selector or record name","selector._domainkey");
    const typeWrap = node("div",null,"dns-field"), typeLabel = node("label","DKIM record type"), dkimType = node("select");dkimType.id = `${prefix}-dkim-type`;typeLabel.htmlFor = dkimType.id;
    for (const value of ["TXT","CNAME"]) {const option=node("option");option.value=value;option.textContent=value;dkimType.append(option);}dkimType.value="TXT";typeWrap.append(typeLabel,dkimType);dkimGrid.append(typeWrap);fields["dkim-type"] = dkimType;dkimType.addEventListener("change",invalidate);
    field(authFields,"dkim-value","DKIM public TXT value or CNAME target","v=DKIM1; k=rsa; p=…",{multiline:true});
    const authError = node("p",null,"form-error");authError.hidden = true;outgoing.append(authError);
    const authRecords = node("div",null,"dns-record-grid");outgoing.append(authRecords);
    const authDetails = technical(outgoing,"SPF and DKIM details",[
      "In relay mode, enable DKIM signing on your outgoing relay and publish its public record. A visible DNS key does not prove outgoing messages are signed.",
      "If you operate your own relay, authorize its actual outbound IP in SPF and obtain the public DKIM record from the software that signs outgoing messages.",
      "Use your relay's actual SPF policy and DKIM selector/value. Keep one SPF record and merge existing senders. The SMTP relay hostname is not necessarily an SPF include domain.",
      "This guide prepares one DKIM selector and SPF at the mail domain. If your relay uses a return-path subdomain, multiple selectors, or additional verification records, publish those separately as required by its configuration.",
      "Paste only the public DKIM record. Private keys and relay passwords never belong in DNS. For a split TXT record, paste all quoted chunks; they will be joined."]);
    const finish = step(4,"DMARC and DNS check","Start with a monitoring policy, publish the records above, then check what public DNS returns.");
    field(finish,"dmarc","DMARC TXT policy","v=DMARC1; p=none",{value:"v=DMARC1; p=none",multiline:true});
    const dmarcError=node("p",null,"form-error");dmarcError.hidden=true;finish.append(dmarcError);
    const policyRecords = node("div",null,"dns-record-grid");finish.append(policyRecords);
    technical(finish,"DMARC policy details",["p=none monitors your mail. Use quarantine or reject only after SPF or DKIM passes and aligns with the mail domain. Add rua only for a real reporting mailbox you can receive at.","If you already have a DMARC policy, reuse or update it. Publish only one DMARC record at _dmarc; do not add a second policy."]);
    const check=node("button","Check public DNS","button primary");check.type="button";check.id=`${prefix}-check`;
    const checkStatus=node("p",null,"field-hint"), checkError=node("p",null,"form-error");checkStatus.id=`${prefix}-check-status`;checkStatus.setAttribute("role","status");checkStatus.setAttribute("aria-live","polite");checkError.setAttribute("role","alert");checkError.hidden=true;
    finish.append(check,checkStatus,checkError,node("p","DNS checks show published records only. They do not test TCP ports, PTR, DKIM signing, SPF/DMARC alignment, or mail delivery.","field-hint"));
    function card(parent,id,label) {
      const item=node("article",null,"dns-record"), heading=node("h4"), status=node("span",null,"dns-record-status"), body=node("div",null,"dns-record-body");
      item.dataset.record=id;heading.append(node("span",label),status);item.append(heading,body);parent.append(item);cards.set(id,{item,status,body});
    }
    for(const [id,label] of [["a","A · server IPv4"],["aaaa","AAAA · server IPv6 (optional)"],["mx","MX · incoming mail"]])card(receiveRecords,id,label);
    card(authRecords,"spf","TXT · SPF");card(authRecords,"dkim","DKIM · outgoing signing");card(policyRecords,"dmarc","TXT · DMARC");
    function copy(parent,label,value) {
      const wrap=node("div",null,"dns-copy"),caption=node("span",label),control=node(value.length>160?"textarea":"input");
      if(control.tagName.toLowerCase()==="input")control.type="text";else control.rows=2;
      control.value=value;control.readOnly=true;control.spellcheck=false;control.setAttribute("aria-label",t(label));control.addEventListener("click",()=>control.select());wrap.append(caption,control);parent.append(wrap);
    }
    function draft() {
      const direct=outboundMode.value==="direct", configured=outboundMode.value==="relay"&&Boolean(clean(inputs.relayHost)), type=direct?"TXT":dkimType.value, name=direct?(currentKey()?keyRecord.name:""):dkimName(clean(fields["dkim-name"]),domain());
      const mechanisms=[publicIpv4(clean(fields.ipv4))?"ip4:"+clean(fields.ipv4):"",publicIpv6(clean(fields.ipv6))?"ip6:"+clean(fields.ipv6):""].filter(Boolean);
      const spf=direct?(mechanisms.length?"v=spf1 "+mechanisms.join(" ")+" -all":""):txtValue(clean(fields.spf)), dkim=direct?(currentKey()?keyRecord.value:""):type==="TXT"?txtValue(clean(fields["dkim-value"])):clean(fields["dkim-value"]), dmarc=txtValue(clean(fields.dmarc));
      return {domain:domain(),hostname:hostname(),ipv4:clean(fields.ipv4),ipv6:clean(fields.ipv6),spf:direct||configured?spf:"",dkim_name:direct||configured?name:"",dkim_type:type,dkim_value:direct||configured?dkim:"",dmarc};
    }
    const selectorValue=()=>clean(selector).toLowerCase(),validSelector=()=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(selectorValue());
    function currentKey(){return keyRecord&&keyRecord.domain===domain()&&keyRecord.selector===selectorValue();}
    function errors(values) {
      const address=(values.ipv4&&!publicIpv4(values.ipv4))||(values.ipv6&&!publicIpv6(values.ipv6));
      const keyTags=values.dkim_value.split(";").map(part=>/^\s*([^=]+?)\s*=\s*(.*?)\s*$/.exec(part)).filter(Boolean), keyVersions=keyTags.filter(tag=>tag[1].trim().toLowerCase()==="v"), keyValues=keyTags.filter(tag=>tag[1].trim().toLowerCase()==="p"),key=(keyValues[0]?.[2]||"").replace(/\s/g,"");
      const badKey=keyVersions.length>1||keyValues.length!==1||(keyVersions.length&&keyVersions[0][2].toLowerCase()!=="dkim1")||!key||!/^[a-z0-9+/=]+$/i.test(key)||/PRIVATE KEY/i.test(values.dkim_value);
      const auth=outboundMode.value==="relay"&&Boolean(clean(inputs.relayHost)) && ((values.spf&&!/^v=spf1(?:\s|$)/i.test(values.spf)) || (clean(fields["dkim-name"])&&!values.dkim_name) || ((values.dkim_value||values.dkim_name)&&(!values.dkim_value||!values.dkim_name)) || (values.dkim_value && (values.dkim_type==="CNAME"?!publicDnsTarget(values.dkim_value.replace(/\.$/,"")):badKey)));
      const tags=values.dmarc.split(";").map(part=>part.trim()).filter(Boolean), names=tags.map(part=>part.split("=")[0].trim().toLowerCase());
      const policy=values.dmarc&&(!/^v\s*=\s*DMARC1\s*;/i.test(values.dmarc)||!/(?:^|;)\s*p\s*=\s*(?:none|quarantine|reject)(?:\s*;|\s*$)/i.test(values.dmarc)||new Set(names).size!==names.length);
      return {address,auth,policy};
    }
    const statuses={matched:"Published value matches",missing:"Record not found",mismatch:"Published value differs",not_configured:"Pending configuration",error:"Lookup unavailable",unchecked:"Not checked",stale:"Changed — check again",skipped:"Optional — not configured"};
    const diagnostics={dns_not_configured:"Enter the expected record value to check it.",dns_matched:"The public record matches your expected value.",dns_missing:"The expected record is not visible yet. Check the name and allow time for DNS propagation.",dns_mismatch:"Review the returned values and update incorrect records at your DNS provider.",dns_multiple_policy_records:"Multiple policies were found. Keep exactly one SPF or DMARC policy at this name.",dns_mx_alias:"The mail hostname is a CNAME alias. An MX target needs direct A/AAAA records.",dns_unexpected_record:"A public address exists without an expected value. Verify it or remove the stale record.",dns_unavailable:"The lookup result is unknown. Allow the server to reach public DNS on outbound UDP 53 and retry.",dns_timeout:"The DNS lookup timed out; its result is unknown. Check network access and retry.",dns_truncated:"The DNS answer was too large. Check this record with your provider's DNS lookup tool.",dns_resolver_failed:"The resolver could not complete this query. Check DNS delegation and DNSSEC.",dns_invalid_response:"The resolver returned an invalid response. Retry this check."};
    function render() {
      const values=draft(),valid=publicDomain(values.domain)&&publicDomain(values.hostname),issues=errors(values), direct=outboundMode.value==="direct",relayMode=outboundMode.value==="relay",relay=relayMode&&Boolean(clean(inputs.relayHost)),authenticated=direct||relay;
      prerequisite.textContent=valid?t("Mail stays at @{domain}; the server address is {hostname}.",{domain:values.domain,hostname:values.hostname}):t("Local mail needs no public DNS. For Internet mail, enter a public mail domain and mail server hostname in step 1.");
      smtp.textContent=t("Receive Internet mail on public TCP 25 → server SMTP port {port}.",{port:clean(inputs.smtpPort)});
      zone.textContent=t("Names assume the zone is {domain}. For a parent zone, use the full names shown or include the missing subdomain.",{domain:values.domain});
      directFields.hidden=!direct;if(relaySettings)relaySettings.hidden=!relayMode;
      relayStatus.hidden=direct;
      relayStatus.textContent=relay?t("Relay: {relay}. Enter the SPF and DKIM records used by this sending server.",{relay:clean(inputs.relayHost)}):relayMode?t("Enter an SMTP relay host, then use its actual SPF and DKIM records."):t("Receiving and local mail only: publish A/AAAA and MX for Internet reception. Outgoing mail to other domains is disabled.");
      authFields.hidden=authDetails.hidden=!relay;authRecords.hidden=!authenticated;
      selector.disabled=!direct;
      generate.disabled=!direct||keyBusy||busy||!publicDomain(domain())||!validSelector();generate.textContent=t(keyBusy?"Generating / loading DKIM…":"Generate / load DKIM public record");
      keyStatus.textContent=keyBusy?t("The private key stays on the server. Waiting for its public DNS record…"):currentKey()?t("Public DKIM key loaded. Fingerprint: {fingerprint}",{fingerprint:keyRecord.fingerprint}):t("Generate or load the key for this domain and selector before saving direct delivery.");
      const keyDetail=keyProblem?PostPlusI18n.error(keyProblem):"";
      keyFailure.hidden=!keyError;keyFailure.textContent=keyError?t(keyError)+(keyDetail&&keyDetail!==t("The request failed. Please try again.")?" "+keyDetail:""):"";
      ptr.replaceChildren();if(publicDomain(hostname()))copy(ptr,"Expected PTR hostname",hostname());
      for(const name of ["spf","dkim-name","dkim-type","dkim-value"])fields[name].disabled=!relay;
      fields["dkim-value"].placeholder=dkimType.value==="CNAME"?"selector.your-provider.example":"v=DKIM1; k=rsa; p=…";
      addressError.hidden=!issues.address;addressError.textContent=t("Use valid public IP addresses. Private, loopback, and documentation addresses cannot receive Internet mail.");
      authError.hidden=!issues.auth;authError.textContent=t("Check your relay's SPF policy and DKIM name, type, and public value. Complete both the DKIM name and value; never paste a private key.");
      dmarcError.hidden=!issues.policy;dmarcError.textContent=t("Use a DMARC policy beginning with v=DMARC1; p=none, quarantine, or reject.");
      const relative=name=>name===values.domain?"@":name.endsWith("."+values.domain)?name.slice(0,-(values.domain.length+1)):name+".";
      const specs={a:{name:values.hostname,type:"A",value:publicIpv4(values.ipv4)?values.ipv4:""},aaaa:{name:values.hostname,type:"AAAA",value:publicIpv6(values.ipv6)?values.ipv6:""},mx:{name:values.domain,type:"MX",value:values.hostname+"."},spf:{name:values.domain,type:"TXT",value:authenticated&&!issues.auth?values.spf:""},dkim:{name:values.dkim_name,type:values.dkim_type,value:authenticated&&!issues.auth?values.dkim_value:""},dmarc:{name:"_dmarc."+values.domain,type:"TXT",value:!issues.policy?values.dmarc:""}};
      for(const [id,{item,status,body}] of cards) {
        const spec=specs[id],found=result?.records.find(record=>record.id.toLowerCase()===id), configured=valid&&Boolean(spec.value)&&Boolean(spec.name);
        let state=configured?(stale?"stale":"unchecked"):id==="aaaa"&&!values.ipv6?"skipped":"not_configured";
        if(found && configured)state=found.status;
        // Existing unexpected AAAA records must remain visible even when no value was entered.
        if(found && ["a","aaaa"].includes(id) && found.status!=="not_configured")state=found.status;
        status.textContent=t(statuses[state]||statuses.error);item.dataset.status=state;body.replaceChildren();
        if(configured){copy(body,"Record type",spec.type);copy(body,"Name / host",relative(spec.name));copy(body,"Full DNS name",spec.name);copy(body,"Value / content",spec.value);if(id==="mx")body.append(node("p","Priority: 10 (separate field)","field-hint"));}
        else body.append(node("p",id==="aaaa"?"Add AAAA only for working public IPv6; remove any stale AAAA at your provider.":id==="spf"||id==="dkim"?"Waiting for the sending server's actual record.":"Enter the required values above to prepare this record.","field-hint"));
        if(found){const observed=node("p",null,"dns-observed"),notQueried=found.status==="not_configured"&&!["a","aaaa"].includes(id);observed.textContent=notQueried?t("Not queried — enter the expected sending-server record first."):t("Public DNS returned: {values}",{values:found.observed.length?found.observed.join(" · "):t(found.status==="error"?"Unknown — lookup failed":"No records returned")});body.append(observed);const explanation=node("p",null,"field-hint");explanation.textContent=t((Object.hasOwn(diagnostics,found.code)?diagnostics[found.code]:"") || (found.status==="error"?diagnostics.dns_unavailable:statuses[found.status]));body.append(explanation);}
      }
      check.disabled=busy||keyBusy||!valid||issues.address||issues.auth||issues.policy;check.textContent=t(busy?"Checking public DNS…":"Check public DNS");checkError.hidden=!errorKey;checkError.textContent=errorKey?t(errorKey):"";
      checkStatus.textContent=busy?t(stale?"Inputs changed. Waiting for the previous DNS query to finish; its results will be discarded.":"Querying public DNS from the server…"):result?t("Checked at {time} via {resolver}.",{time:result.checked_at,resolver:result.resolver}):stale?t("Your inputs changed. Previous results are no longer current."):t("Records have not been checked. Publishing or copying a value does not verify it.");
    }
    function invalidate(){if(disposed)return;version++;stale=Boolean(result)||busy||stale;result=null;errorKey="";render();}
    function invalidateKey(){keyRevision++;keyRecord=null;keyError="";keyProblem=null;invalidate();}
    function syncHostname(){if(!hostnameEdited||!clean(inputs.hostname)){inputs.hostname.value=publicDomain(domain())?"mail."+domain():"";onHostnameChange?.(hostname());}}
    inputs.domain.addEventListener("input",()=>{syncHostname();invalidateKey();});
    inputs.hostname.addEventListener("input",()=>{hostnameEdited=true;onHostnameChange?.(hostname());invalidate();});
    inputs.relayHost.addEventListener("input",invalidate);inputs.smtpPort.addEventListener("input",invalidate);
    selector.addEventListener("input",invalidateKey);
    outboundMode.addEventListener("change",()=>{modeEdited=true;invalidate();});
    generate.addEventListener("click",async()=>{
      if(generate.disabled||disposed)return;const expected={domain:domain(),selector:selectorValue()},revision=++keyRevision;keyBusy=true;keyError="";keyProblem=null;keyRecord=null;invalidate();
      try{
        const data=await generateDkim?.(expected);if(disposed||revision!==keyRevision)return;
        const value=typeof data?.value==="string"?txtValue(data.value):"",tags=value.split(";").map(part=>/^\s*([^=]+?)\s*=\s*(.*?)\s*$/.exec(part)).filter(Boolean),names=tags.map(tag=>tag[1].toLowerCase()),key=tags.find(tag=>tag[1].toLowerCase()==="p")?.[2];
        if(!data?.ok||data.domain!==expected.domain||data.selector!==expected.selector||data.name!==dkimName(expected.selector,expected.domain)||data.type!=="TXT"||typeof data.fingerprint!=="string"||!data.fingerprint||!/^(?:v=DKIM1)(?:;|\s)/i.test(value)||new Set(names).size!==names.length||!key||!/^[a-z0-9+/=]+$/i.test(key)||/PRIVATE KEY/i.test(JSON.stringify(data))||Object.keys(data).some(name=>/private|secret/i.test(name)))throw new Error("invalid_response");
        keyRecord={domain:expected.domain,selector:expected.selector,name:data.name,type:"TXT",value,fingerprint:data.fingerprint};invalidate();
      }catch(problem){if(!disposed&&revision===keyRevision){keyProblem=problem?.code==="setup_busy"?null:problem;keyError=problem?.code==="setup_busy"?"Another setup operation is still running. Wait for it to finish, then load DKIM again.":"Cannot generate or load the public DKIM record. Check the server error and retry.";}}
      finally{if(!disposed){keyBusy=false;render();}}
    });
    check.addEventListener("click",async()=>{
      if(check.disabled||disposed)return;const values=draft(),revision=++version;snapshotStart();
      function snapshotStart(){busy=true;result=null;errorKey="";render();}
      try {
        const data=await request(values);if(disposed||revision!==version)return;
        if(!data?.ok||!Array.isArray(data.records)||typeof data.checked_at!=="string"||typeof data.resolver!=="string"||data.records.some(item=>!item||typeof item.id!=="string"||!["matched","missing","mismatch","not_configured","error"].includes(item.status)||!Array.isArray(item.observed)||item.observed.some(value=>typeof value!=="string")))throw new Error("invalid_response");
        const ids=new Set(data.records.map(item=>item.id.toLowerCase()));if(data.records.length!==6||ids.size!==6||[...ids].some(id=>!cards.has(id)))throw new Error("invalid_response");
        result=data;stale=false;
      }catch(problem){if(disposed||revision!==version)return;errorKey=problem?.code==="invalid_dns_input"?"Check the DNS inputs before retrying.":problem?.code==="setup_busy"?"Another setup operation is still running. Wait for it to finish, then check DNS again.":"DNS lookup could not be completed. Check the server's network access and try again.";}
      finally{if(!disposed){busy=false;render();}}
    });
    if(hostnameEdited)onHostnameChange?.(hostname());else syncHostname();render();
    return {refresh:invalidate,translate(){PostPlusI18n.apply(root);render();},read:draft,
      settings:()=>({outbound_mode:outboundMode.value,dkim_selector:selectorValue(),...(outboundMode.value==="direct"&&currentKey()?{dkim_fingerprint:keyRecord.fingerprint}:{})}),
      directReady:()=>outboundMode.value!=="direct"||Boolean(!keyBusy&&currentKey()&&publicDomain(hostname())&&validSelector()),
      suggestMode:value=>{if(!modeEdited&&["direct","relay","disabled"].includes(value)){outboundMode.value=value;invalidate();}},
      dispose(){disposed=true;version++;keyRevision++;},get hostname(){return hostname();}};
  }
  return {create,publicDomain,publicDnsTarget,publicIpv4,publicIpv6,dkimName,txtValue};
})();
