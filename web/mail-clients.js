"use strict";
// Client and discovery guidance describes the form's configuration, not a network probe.
window.PostPlusMailClients = (() => {
  const t = (...args) => PostPlusI18n.t(...args);
  const publicDomain = value => typeof value === "string" && value.length <= 253 && value.includes(".") && !/^\d+(?:\.\d+){3}$/.test(value) && !/(?:^|\.)(?:localhost|local|test|invalid|example)$/.test(value) && value.split(".").every(label => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
  const clean = value => typeof value === "string" ? value.trim() : "";
  const port = value => Number.isSafeInteger(Number(value)) && Number(value) > 0 && Number(value) <= 65535 ? Number(value) : 0;
  function standardPorts(secure) {
    return {smtp:25,pop3:110,imap:143,web:secure?443:80,submission:587,smtps:465,pop3s:995,imaps:993};
  }
  const legacyPorts = ports => Object.entries({smtp:2525,pop3:1110,imap:1143,web:8080}).some(([name,value])=>Number(ports?.[name])===value);
  function model(config = {}) {
    const domain = clean(config.domain).toLowerCase();
    const hostname = clean(config.mail_hostname).toLowerCase() || (publicDomain(domain) && !domain.startsWith("mail.") ? "mail." + domain : domain);
    const tls = Boolean(clean(config.tls_certificate) && clean(config.tls_private_key));
    const local = ["127.0.0.1","::1","localhost"].includes(clean(config.bind).toLowerCase());
    const username = clean(config.client_username) || (domain ? "yourname@" + domain : "");
    const ports = config.ports || {}, rows = [], records = [];
    function service(id, protocol, direction, security, srv, enabled, recommended = false) {
      const value = port(ports[id]);
      if (!enabled || !value) return;
      rows.push({id,protocol,direction,security,hostname:local&&!tls?clean(config.bind):hostname,port:value,username,recommended});
      if (tls && !local && publicDomain(domain) && publicDomain(hostname)) records.push({type:"SRV",name:srv + "." + domain,host:srv,value:`0 1 ${value} ${hostname}.`,port:value,target:hostname + "."});
    }
    const authenticated = tls || local && config.allow_insecure_auth === true;
    service("imaps","IMAP","Incoming mail","SSL/TLS","_imaps._tcp",tls,true);
    service("imap","IMAP","Incoming mail",tls?"STARTTLS":"None (local only)","_imap._tcp",authenticated,!tls||!port(ports.imaps));
    service("pop3s","POP3","Incoming mail","SSL/TLS","_pop3s._tcp",tls);
    service("pop3","POP3","Incoming mail",tls?"STARTTLS":"None (local only)","_pop3._tcp",authenticated);
    service("submission","SMTP","Outgoing mail","STARTTLS","_submission._tcp",tls,true);
    service("smtps","SMTP","Outgoing mail","SSL/TLS","_submissions._tcp",tls,!port(ports.submission));
    service("smtp","SMTP","Outgoing mail","None (local only)","",local && config.allow_insecure_auth === true && !tls,true);
    const webPort = port(ports.web);
    // Use the configured local bind for local mode, so the guide does not promise public access.
    const webHost = local ? (clean(config.bind) === "::1" ? "[::1]" : clean(config.bind)) : hostname;
    const validHost = /^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?|\[::1\])$/i.test(webHost);
    const webUrl = webPort && validHost ? `${tls?"https":"http"}://${webHost}${webPort===(tls?443:80)?"":":"+webPort}/` : "";
    const discovery = tls && !local && webPort===443 && publicDomain(domain) && publicDomain(hostname) && rows.some(row=>row.direction==="Incoming mail") && rows.some(row=>row.direction==="Outgoing mail");
    if(discovery)records.push({type:"SRV",name:"_autodiscover._tcp."+domain,host:"_autodiscover._tcp",value:`0 1 443 ${hostname}.`,port:443,target:hostname+"."});
    return {domain,hostname,username,tls,local,rows,records,webUrl,discovery,outboundMode:config.outbound_mode,autoconfigUrl:discovery?`https://${hostname}/.well-known/autoconfig/mail/config-v1.1.xml`:"",autodiscoverUrl:discovery?`https://${hostname}/autodiscover/autodiscover.xml`:""};
  }
  function configurationText(value) {
    const lines = [t("Mail server hostname") + ": " + value.hostname,t("Username (full email address)") + ": " + value.username,t("Password: the password for this mailbox.")];
    for (const row of value.rows) lines.push(`${t(row.direction)} · ${row.protocol}: ${row.hostname}:${row.port}, ${t(row.security)}, ${t("Password authentication")}`);
    if (value.webUrl) lines.push(t("Webmail") + ": " + value.webUrl);
    if(value.outboundMode==="disabled")lines.push(t("Outgoing delivery to other domains is disabled. SMTP submission can send local mail only."));
    return lines.join("\n");
  }
  function create(root, {readConfig, prefix="mail-clients"} = {}) {
    let disposed = false, current = null, copied = false, selected = false, revision = 0;
    function node(tag, text, className) {const result = document.createElement(tag);if(text){result.dataset.i18n=text;result.textContent=t(text);}if(className)result.className=className;return result;}
    root.replaceChildren();
    const summary = node("p",null,"dns-prerequisite"), rows = node("div",null,"mail-client-grid"), web = node("p",null,"field-hint"), warning = node("p",null,"field-hint");
    const copyLabel = node("label","Copy client configuration"), text = node("textarea",null,"mail-client-copy"), copyButton = node("button","Copy client configuration","button secondary"), copyStatus = node("p",null,"field-hint");
    text.id=`${prefix}-copy`;text.readOnly=true;text.rows=5;text.spellcheck=false;copyLabel.htmlFor=text.id;copyButton.type="button";copyButton.id=`${prefix}-copy-button`;copyStatus.setAttribute("role","status");copyStatus.setAttribute("aria-live","polite");text.addEventListener("click",()=>text.select());
    const discovery = node("details",null,"mail-discovery"), discoveryHeading = node("summary","Optional DNS for mail apps"), discoveryIntro = node("p","SRV records help compatible mail apps find these services. Add only the records for services you enable, using DNS-only mode.","field-hint"), records = node("div",null,"dns-record-grid"), endpoints=node("div",null,"mail-discovery-endpoints"), discoveryHint=node("p",null,"field-hint");
    discovery.append(discoveryHeading,discoveryIntro,records,endpoints,discoveryHint,node("p","SRV value order is priority, weight, port, target. If your DNS provider uses separate fields, enter 0, 1, the port, and the mail hostname. A successful DNS lookup does not test the listener or certificate.","field-hint"));
    root.append(summary,rows,web,warning,copyLabel,text,copyButton,copyStatus,discovery);
    function copyField(parent,label,value) {const wrap=node("div",null,"dns-copy"),caption=node("span",label),input=node("input");input.type="text";input.readOnly=true;input.spellcheck=false;input.value=value;input.setAttribute("aria-label",t(label));input.addEventListener("click",()=>input.select());wrap.append(caption,input);parent.append(wrap);}
    function status() {copyStatus.textContent=t(copied?"Client configuration copied.":selected?"The configuration is selected. Copy it with Ctrl+C or your device's copy command.":"Use your full email address and mailbox password. Never use the one-time setup password or an administration API key.");}
    function render() {
      if(disposed)return;revision++;current=model(readConfig?.() || {});copied=selected=false;
      summary.textContent=t("Client settings follow the values in this form. Save the configuration and allow the displayed ports through your firewall before connecting.");
      rows.replaceChildren();
      for(const row of current.rows){
        const card=node("article",null,"mail-client-card"),title=node("h3");title.textContent=`${row.protocol} · ${t(row.direction)}${row.recommended?" · "+t("Recommended"):""}`;card.dataset.service=row.id;
        card.append(title);copyField(card,"Server",row.hostname);copyField(card,"Port",String(row.port));copyField(card,"Connection security",t(row.security));copyField(card,"Username (full email address)",row.username);card.append(node("p","Password authentication","field-hint"));rows.append(card);
      }
      web.hidden=!current.webUrl;web.textContent=current.webUrl?t("Webmail address: {url}",{url:current.webUrl}):"";
      warning.textContent=current.local?t("Local mode is available only on the server itself. Choose TLS and a network listen address to connect from another computer."):!current.tls?t("Configure a certificate and private key to enable secure mailbox access. Dedicated TLS ports remain inactive without both files."):!current.rows.some(row=>row.direction==="Outgoing mail")?t("Enable SMTP submission or SMTPS to send from mail apps. SMTP port 25 receives mail from other servers."):current.outboundMode==="disabled"?t("Outgoing delivery to other domains is disabled. SMTP submission can send local mail only."):t("SMTP port 25 receives Internet mail. Mail apps send with authentication on the submission or SMTPS port. IMAP keeps mail synchronized; POP3 downloads mail.");
      text.value=configurationText(current);copyButton.disabled=!current.hostname;status();records.replaceChildren();
      for(const record of current.records){const card=node("article",null,"dns-record");card.dataset.record=record.host;card.append(node("h4","SRV · mail app discovery"));copyField(card,"Record type",record.type);copyField(card,"Name / host",record.host);copyField(card,"Full DNS name",record.name);copyField(card,"Value / content",record.value);records.append(card);}
      if(!current.records.length)records.append(node("p","Client discovery records appear when a public mail domain, public hostname, network listen address, and TLS certificate are configured.","field-hint"));
      endpoints.replaceChildren();if(current.discovery){copyField(endpoints,"Thunderbird autoconfig URL",current.autoconfigUrl);copyField(endpoints,"Autodiscover URL",current.autodiscoverUrl);}
      discoveryHint.textContent=t(current.discovery?"Autoconfig and Autodiscover are served at the mail hostname. Some mail apps still require manual setup. Keep the certificate valid for this hostname; aliases such as autoconfig or autodiscover need their own certificate coverage.":"HTTPS Webmail on port 443 and enabled incoming and submission services are required for the discovery endpoints. Manual client settings remain available on custom ports.");
      discoveryIntro.textContent=t("SRV records help compatible mail apps find these services. Add only the records for services you enable, using DNS-only mode.");discoveryHeading.textContent=t("Optional DNS for mail apps");copyLabel.textContent=copyButton.textContent=t("Copy client configuration");
    }
    copyButton.addEventListener("click",async()=>{
      if(disposed||copyButton.disabled)return;const copiedRevision=revision,contents=text.value;
      try {if(!navigator.clipboard?.writeText)throw new Error("clipboard_unavailable");await navigator.clipboard.writeText(contents);if(disposed||copiedRevision!==revision)return;copied=true;selected=false;}
      catch {if(disposed||copiedRevision!==revision)return;text.focus();text.select();copied=false;selected=true;}
      status();
    });
    render();return {render,translate(){PostPlusI18n.apply(root);render();},dispose(){disposed=true;revision++;text.value="";root.replaceChildren();}};
  }
  return {create,model,standardPorts,legacyPorts,configurationText};
})();
