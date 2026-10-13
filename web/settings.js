"use strict";
// The same typed settings form is used during setup and in administration.
window.PostPlusSettings = (() => {
  const t = (...args) => PostPlusI18n.t(...args);
  const groups = {
    general:["General", "Your domain and the folders that make this server yours."],
    network:["Network", "Separate addresses and ports for administration, Webmail, and mail clients."],
    security:["Security", "Certificates, authentication, and connection protection."],
    limits:["Connection and message limits", "Choose sensible limits for mail clients and message uploads."],
    delivery:["Outgoing mail", "Choose built-in direct delivery, an SMTP relay, or receiving and local mail only."],
    filter:["Mail filtering", "Choose how suspicious mail and antivirus failures are handled."],
    storage:["Storage and limits", "Set message sizes, account quotas, and delivery limits."],
    logging:["Logging", "Keep useful service events without using unlimited disk space."],
    paths:["Server folders", "Review where your server stores its data and web pages."]
  };
  const get = (source, key) => key.split(".").reduce((value, part) => value?.[part], source);
  function set(target, key, value) {
    const parts = key.split(".");
    if (parts.some(part => ["__proto__", "constructor", "prototype"].includes(part))) throw new Error("Invalid field path");
    let item = target;
    for (const part of parts.slice(0,-1)) item = item[part] ||= {};
    item[parts.at(-1)] = value;
  }
  function node(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined) { item.dataset.i18n = text; item.textContent = t(text); }
    return item;
  }
  function reveal(input) {
    for (let section=input.closest("details"); section; section=section.parentElement?.closest("details")) section.open=true;
    input.setAttribute("aria-invalid","true");
    input.focus();
  }
  function create(root, schema, values, options = {}) {
    const controls = new Map();
    let deliverySection=null,dkimPanel=null,clientPanel=null,disposed=false;
    const clientEvents=[];
    const prefix = options.prefix || "settings";
    root.replaceChildren();
    for (const [group, [title, description]] of Object.entries(groups)) {
      const fields = schema.filter(field => field.group === group && !options.exclude?.has(field.key));
      if (!fields.length) continue;
      const section = node("details", "settings-group");
      if(group==="delivery")deliverySection=section;
      section.open = group === "general";
      section.append(node("summary", "", title), node("p", "field-hint", description));
      const grid = node("div", "settings-grid");
      for (const field of fields) {
        const wrapper = node("div", `setting-field ${["lines","json"].includes(field.type) ? "wide" : ""}`);
        const id = `${prefix}-${field.key.replaceAll(".","-")}`;
        const label = node("label", "", field.label);
        label.htmlFor = id;
        const input = node(field.type === "select" || field.type === "boolean" ? "select" : ["lines","json"].includes(field.type) ? "textarea" : "input");
        input.id = id;
        input.dataset.configKey = field.key;
        const initial = get(values, field.key) ?? field.default ?? "";
        if (field.type === "boolean" || field.type === "select") {
          const deliveryLabels={disabled:"Receive and local mail only",direct:"Direct delivery — recommended for your own server",relay:"Send through an SMTP relay"};
          const directTlsLabels={starttls:"STARTTLS when available",required:"Require verified TLS"};
          const choices = field.type === "boolean" ? [["true","Enabled"],["false","Disabled"]] : (field.options || []).map(value => [value,field.key==="outbound_mode"?deliveryLabels[value]||value:field.key==="direct_tls"?directTlsLabels[value]||value:value]);
          for (const [value, text] of choices) { const choice = node("option", "", text); choice.value = value; input.append(choice); }
          input.value = String(initial);
        } else {
          if (!["lines","json"].includes(field.type))
            input.type = field.type === "number" ? "number" : field.type === "password" ? "password" : "text";
          input.value = field.type === "password" ? "" : field.type === "lines" ? (Array.isArray(initial) ? initial.join("\n") : String(initial)) : field.type === "json" ? JSON.stringify(initial,null,2) : String(initial);
          if (field.type === "password") input.autocomplete = "new-password";
          else input.autocomplete = "off";
          input.spellcheck = false;
          if (field.type === "number") { input.step = "1"; if (field.min !== undefined) input.min = field.min; if (field.max !== undefined) input.max = field.max; }
          if (field.maxlength !== undefined) input.maxLength = field.maxlength;
          if (["lines","json"].includes(field.type)) input.rows = field.type === "json" ? 5 : 3;
        }
        input.disabled = Boolean(field.readonly);
        input.setAttribute("aria-describedby",`${id}-help`);
        const help = node("p", "field-hint", field.help || "");
        help.id = `${id}-help`;
        let sizeControl=null;
        if(field.unit === "bytes") {
          const unit=node("select");unit.id=`${id}-unit`;unit.setAttribute("data-i18n-aria-label","Size unit");unit.setAttribute("aria-label",t("Size unit"));unit.disabled=input.disabled;
          sizeControl=PostPlusSize.create(input,unit,Number(initial),{min:field.min,max:field.max});
          const size=node("div","size-control");size.append(input,unit);wrapper.append(label,size,help);
        } else wrapper.append(label,input,help);
        if (field.readonly) wrapper.append(node("p","field-hint readonly-hint",field.key==="dkim_private_key"?"Use Generate / load DKIM public record below. The private key stays on this server.":"Managed by the server. Change this in the configuration file while PostPlus is stopped."));
        let clearPassword = null;
        if (field.type === "password") {
          wrapper.append(node("p","field-hint", options.secretStatus?.[field.key] ? "A password is saved. Leave blank to keep it." : "No password is saved. Leave blank to use the environment variable."));
          if (options.secretStatus?.[field.key] && field.key === "smarthost_password") {
            const clearLabel = node("label","checkbox-label");
            clearPassword = node("input");
            clearPassword.type = "checkbox";
            clearLabel.append(clearPassword,node("span","","Remove the saved relay password"));
            wrapper.append(clearLabel);
            clearPassword.addEventListener("change",() => {input.disabled = clearPassword.checked; if(clearPassword.checked) input.value = "";});
          }
        }
        input.addEventListener("input", () => input.removeAttribute("aria-invalid"));
        controls.set(field.key,{field,input,initial:sizeControl ? Number(initial) : input.value,clearPassword,sizeControl});
        grid.append(wrapper);
      }
      section.append(grid);
      root.append(section);
    }
    if(options.mailClients && window.PostPlusMailClients){
      const networkSection=[...root.children].find(section=>section.querySelector?.('[data-config-key="ports.smtp"]'));
      function clientConfig(){
        const result={...values,ports:{...values.ports}};
        for(const key of ["domain","mail_hostname","bind","allow_insecure_auth","tls_certificate","tls_private_key","outbound_mode",...Object.keys(values.ports || {}).map(name=>"ports."+name)]){
          const control=controls.get(key);if(control)set(result,key,control.field.type==="number"?Number(control.input.value):control.field.type==="boolean"?control.input.value==="true":control.input.value);
        }
        // Newly introduced listeners may not be present in an older saved configuration.
        for(const name of ["submission","smtps","pop3s","imaps"]){const control=controls.get("ports."+name);if(control)result.ports[name]=Number(control.input.value);}
        return result;
      }
      if(networkSection){
        const preset=node("div","standard-ports"),button=node("button","button secondary","Apply standard ports"),hint=node("p","field-hint","Existing custom ports stay unchanged until you apply this preset and save."),legacy=node("p","legacy-port-hint","Legacy port values detected. Apply standard ports and save to switch to public defaults.");
        legacy.hidden=!PostPlusMailClients.legacyPorts(clientConfig().ports);legacy.setAttribute("role","status");
        button.type="button";button.id=`${prefix}-standard-ports`;hint.setAttribute("role","status");hint.setAttribute("aria-live","polite");preset.append(legacy,node("p","field-hint","Public defaults are SMTP 25, POP3 110, IMAP 143, and Webmail 80 (443 with TLS). On Unix, grant PostPlus permission to bind privileged ports."),button,hint);networkSection.insertBefore(preset,networkSection.children[2]);
        const clients=node("section","mail-clients");clients.append(node("h3","","Connect mail apps"));const guide=node("div");clients.append(guide);networkSection.append(clients);
        clientPanel=PostPlusMailClients.create(guide,{readConfig:clientConfig,prefix:`${prefix}-clients`});
        button.addEventListener("click",()=>{
          const config=clientConfig(),secure=Boolean(config.tls_certificate?.trim()&&config.tls_private_key?.trim());
          for(const [name,value] of Object.entries(PostPlusMailClients.standardPorts(secure))){const control=controls.get("ports."+name);if(control&&!control.field.readonly){control.input.value=String(value);control.input.removeAttribute("aria-invalid");}}
          hint.dataset.i18n="Standard ports are filled in. Save the configuration to apply them.";hint.textContent=t(hint.dataset.i18n);legacy.hidden=!PostPlusMailClients.legacyPorts(clientConfig().ports);clientPanel.render();
        });
        const updateClients=event=>{if(!disposed&&!event.target.closest?.(".mail-clients")){legacy.hidden=!PostPlusMailClients.legacyPorts(clientConfig().ports);clientPanel?.render();}};for(const event of ["input","change"]){root.addEventListener(event,updateClients);clientEvents.push([event,updateClients]);}
      }
    }
    if(options.generateDkim&&deliverySection&&["domain","outbound_mode","dkim_selector"].every(key=>controls.has(key))){
      const panel=node("section","settings-dkim"),button=node("button","button primary","Generate / load DKIM public record"),status=node("p","field-hint"),error=node("p","form-error"),record=node("div","dns-record-grid");
      button.type="button";button.id=`${prefix}-generate-dkim`;status.setAttribute("role","status");error.setAttribute("role","alert");panel.append(node("h3","","DKIM public DNS record"),node("p","field-hint","Publish this TXT record at your DNS provider. Only the public key is shown; keep private backups secure."),button,status,error,record);deliverySection.append(panel);
      const current=()=>({domain:controls.get("domain").input.value.trim().toLowerCase(),selector:controls.get("dkim_selector").input.value.trim().toLowerCase()}),direct=()=>controls.get("outbound_mode").input.value==="direct";
      let revision=0,busy=false,publicRecord=null,errorKey="",errorProblem=null;
      function currentKey(){const expected=current();return publicRecord&&publicRecord.domain===expected.domain&&publicRecord.selector===expected.selector;}
      function ready(){const expected=current();return !busy&&(currentKey()||Boolean(values.dkim_private_key&&expected.domain===String(values.domain).toLowerCase()&&expected.selector===String(values.dkim_selector||"postplus").toLowerCase()));}
      function copy(label,value){const wrap=node("div","dns-copy"),input=node("textarea");input.rows=value.length>160?3:1;input.readOnly=true;input.value=value;input.setAttribute("aria-label",t(label));input.addEventListener("click",()=>input.select());wrap.append(node("span","",label),input);record.append(wrap);}
      function render(){
        panel.hidden=!direct();button.disabled=busy;button.textContent=t(busy?"Generating / loading DKIM…":"Generate / load DKIM public record");
        status.textContent=busy?t("The private key stays on the server. Waiting for its public DNS record…"):currentKey()?t("Public DKIM key loaded. Fingerprint: {fingerprint}",{fingerprint:publicRecord.fingerprint}):t("Generate or load the key for this domain and selector before saving direct delivery.");
        const detail=errorProblem?PostPlusI18n.error(errorProblem):"";
        error.hidden=!errorKey;error.textContent=errorKey?t(errorKey)+(detail&&detail!==t("The request failed. Please try again.")?" "+detail:""):"";record.replaceChildren();if(currentKey()){copy("Full DNS name",publicRecord.name);copy("Value / content",publicRecord.value);}
      }
      function invalidate(){revision++;publicRecord=null;errorKey="";errorProblem=null;render();}
      for(const key of ["domain","dkim_selector"])controls.get(key).input.addEventListener("input",invalidate);
      controls.get("outbound_mode").input.addEventListener("change",render);
      button.addEventListener("click",async()=>{
        if(busy||disposed)return;const expected=current(),requested=++revision;busy=true;publicRecord=null;errorKey="";errorProblem=null;render();
        try{
          const data=await options.generateDkim(expected);if(disposed||requested!==revision)return;
          const tags=typeof data?.value==="string"?data.value.split(";").map(part=>/^\s*([^=]+?)\s*=\s*(.*?)\s*$/.exec(part)).filter(Boolean):[],names=tags.map(tag=>tag[1].toLowerCase()),tag=name=>tags.find(item=>item[1].toLowerCase()===name)?.[2];
          if(!data?.ok||data.domain!==expected.domain||data.selector!==expected.selector||data.type!=="TXT"||data.name!==expected.selector+"._domainkey."+expected.domain||tag("v")!=="DKIM1"||tag("k")!=="rsa"||!tag("p")||!/^[a-z0-9+/=]+$/i.test(tag("p"))||new Set(names).size!==names.length||typeof data.fingerprint!=="string"||!data.fingerprint||/PRIVATE KEY/i.test(JSON.stringify(data))||Object.keys(data).some(key=>/private|secret/i.test(key)))throw new Error("invalid_response");
          publicRecord={domain:expected.domain,selector:expected.selector,name:data.name,value:data.value,fingerprint:data.fingerprint};
        }catch(problem){if(!disposed&&requested===revision){errorProblem=problem?.data||problem;errorKey="Cannot generate or load the public DKIM record. Check the server error and retry.";}}
        finally{if(!disposed){busy=false;render();}}
      });
      dkimPanel={render,check(){if(direct()&&!ready()){deliverySection.open=true;button.focus();throw new Error(t("Generate or load the DKIM public record for the current domain and selector before saving direct delivery."));}},dispose(){revision++;}};render();
    }
    function read({changedOnly = true} = {}) {
      dkimPanel?.check();
      const result = {};
      for (const [key,{field,input,initial,clearPassword,sizeControl}] of controls) {
        if (clearPassword?.checked) {result.clear_smarthost_password = true; continue;}
        if (field.readonly || (!sizeControl && changedOnly && input.value === initial)) continue;
        if (field.type === "password" && !input.value) continue;
        let value;
        try {
          if (!input.checkValidity() || !sizeControl && field.type === "number" && (!input.value || !Number.isSafeInteger(Number(input.value)))) throw new Error();
          value = sizeControl ? sizeControl.read() : field.type === "number" ? Number(input.value) : field.type === "boolean" ? input.value === "true" : field.type === "lines" ? input.value.split(/\r?\n/).map(line => line.trim()).filter(Boolean) : field.type === "json" ? JSON.parse(input.value) : field.type === "password" ? input.value : input.value.trim();
          if(sizeControl && changedOnly && value===initial) continue;
        } catch {
          reveal(input);
          throw new Error(t("Check the value for {field}.",{field:t(field.label)}));
        }
        set(result,key,value);
      }
      return result;
    }
    return {read,translate:() => {PostPlusI18n.apply(root);dkimPanel?.render();clientPanel?.translate();},dispose(){disposed=true;dkimPanel?.dispose();clientPanel?.dispose();for(const [event,handler] of clientEvents)root.removeEventListener(event,handler);},highlight:key => {const control = controls.get(key); if(control) reveal(control.input);},clearSecrets:() => controls.forEach(({field,input}) => {if(field.type === "password") input.value = "";})};
  }
  return {create};
})();
