"use strict";
window.PostPlusAdminAbuseIPDB={mount(root,{api,notice=()=>{}}){
  const t=(...args)=>PostPlusI18n.t(...args),labels=[],fields={},controls=[],durations=[];
  let active=true,version=0,loaded=false,busy=false,revision=null,snapshot=null,quotas=[],automation=null,editingKey=false,quotaStatusKey="";
  const node=(tag,key,className)=>{const e=document.createElement(tag);if(className)e.className=className;if(key){labels.push({e,key});e.textContent=t(key);}return e;};
  const button=key=>{const e=node("button",key,"button secondary");e.type="button";return e;};
  function field(parent,key,label,{type="text",min,max,value,required=false}={}){
    const wrap=node("div",null,"security-field"),caption=node("label",label),input=node(type==="textarea"?"textarea":"input");
    input.id="abuse-"+key;caption.htmlFor=input.id;if(type!=="textarea")input.type=type;input.required=required;
    if(min!==undefined)input.min=String(min);if(max!==undefined)input.max=String(max);if(value!==undefined)input.value=String(value);if(type==="number")input.step="1";
    wrap.append(caption,input);parent.append(wrap);controls.push(input);return input;
  }
  function checkbox(parent,key,label){const wrap=node("label",null,"checkbox-label"),input=node("input"),caption=node("span",label);input.type="checkbox";input.id="abuse-"+key;wrap.append(input,caption);parent.append(wrap);controls.push(input);return input;}
  function exactValue(value,factor){
    const text=String(value),match=text.match(/^(?:(\d+)(?:\.(\d*))?|\.(\d+))(?:[eE]([+-]?\d+))?$/);
    if(!match||text.length>80)return NaN;
    const fraction=match[2]||match[3]||"",exponent=Number(match[4]||0)-fraction.length;
    if(!Number.isInteger(exponent)||Math.abs(exponent)>100)return NaN;
    let numerator=BigInt((match[1]||"0")+fraction)*BigInt(factor),denominator=1n;
    if(exponent>=0)numerator*=10n**BigInt(exponent);else denominator=10n**BigInt(-exponent);
    if(numerator%denominator!==0n)return NaN;
    const result=Number(numerator/denominator);return Number.isSafeInteger(result)?result:NaN;
  }
  function durationField(parent,key,label,min,max,{days=false}={}){
    const units=days?{days:1,weeks:7}:{seconds:1,minutes:60,hours:3600,days:86400};
    const names={seconds:"Seconds",minutes:"Minutes",hours:"Hours",days:"Days",weeks:"Weeks"};
    const wrap=node("div",null,"security-field security-duration"),caption=node("label",label),row=node("div",null,"security-duration-controls"),input=node("input"),unit=node("select"),hint=node("p",null,"field-hint security-duration-hint");
    input.id="abuse-"+key;input.type="number";input.step="any";input.required=true;caption.htmlFor=input.id;unit.id=input.id+"-unit";hint.id=input.id+"-hint";input.setAttribute("aria-describedby",hint.id);unit.setAttribute("aria-describedby",hint.id);
    for(const [value] of Object.entries(units)){const option=node("option",names[value]);option.value=value;unit.append(option);}
    let selected=Object.keys(units)[0],valueSnapshot=null;unit.value=selected;
    const read=()=>valueSnapshot&&valueSnapshot.value===input.value&&valueSnapshot.unit===selected?valueSnapshot.valueInBase:exactValue(input.value,units[selected]);
    const valid=()=>Number.isSafeInteger(read())&&read()>=min&&read()<=max;
    function translate(){unit.setAttribute("aria-label",t("{field} unit",{field:t(label)}));hint.textContent=t(days?"Use {min} to {max} whole days.":"Use {min} to {max} whole seconds.",{min,max});}
    function clearError(){input.setCustomValidity("");translate();}
    function set(value,chosen){selected=chosen||Object.keys(units).reverse().find(name=>value%units[name]===0)||Object.keys(units)[0];unit.value=selected;input.min=String(min/units[selected]);input.max=String(max/units[selected]);input.value=String(value/units[selected]);valueSnapshot={valueInBase:value,value:input.value,unit:selected};clearError();}
    unit.addEventListener("change",()=>{const value=read(),next=unit.value;if(!Object.hasOwn(units,next)){unit.value=selected;return;}if(Number.isSafeInteger(value))set(value,next);else{selected=next;valueSnapshot=null;input.min=String(min/units[selected]);input.max=String(max/units[selected]);clearError();}});
    input.addEventListener("input",clearError);input.addEventListener("change",clearError);row.append(input,unit);wrap.append(caption,row,hint);parent.append(wrap);controls.push(input,unit);
    const duration={input,unit,set,read,translate,validate(){const ok=valid();input.setCustomValidity(ok?"":t(days?"Use {min} to {max} whole days.":"Use {min} to {max} whole seconds.",{min,max}));return ok;}};durations.push(duration);translate();return duration;
  }
  root.replaceChildren();
  const intro=node("div",null,"section-heading"),copy=node("div"),title=node("h2","AbuseIPDB"),help=node("p","Check IP reputation, review API capacity, and act on abusive sign-in attempts.","muted"),refreshButton=button("Refresh AbuseIPDB");copy.append(title,help);intro.append(copy,refreshButton);
  const error=node("p",null,"form-error"),status=node("p",null,"muted");error.hidden=true;error.setAttribute("role","alert");status.setAttribute("role","status");status.setAttribute("aria-live","polite");
  const credentials=node("div",null,"abuse-credentials"),keyCard=node("section",null,"settings-group abuse-key-card"),keyTitle=node("h3","AbuseIPDB API key"),keySummary=node("div",null,"abuse-key-summary"),keyState=node("p",null,"abuse-key-state"),keyPlaceholder=node("input"),modifyKey=button("Modify API key"),keyForm=node("form"),keyEditor=node("div",null,"abuse-key-editor");
  keyForm.id="abuse-key-form";keyEditor.id="abuse-key-editor";keyPlaceholder.id="abuse-key-placeholder";keyPlaceholder.type="text";keyPlaceholder.readOnly=true;keyPlaceholder.setAttribute("aria-label",t("Saved API key"));keyPlaceholder.value="";keySummary.append(keyPlaceholder,keyState,modifyKey);
  const apiKey=field(keyEditor,"api-key","New API key",{type:"password"});apiKey.autocomplete="new-password";apiKey.maxLength=512;
  const advanced=node("details",null,"abuse-key-advanced"),advancedTitle=node("summary","Advanced key source"),apiKeyEnv=field(advanced,"api-key-env","API key environment variable"),envHint=node("p","An environment key takes precedence over a saved key. Leave the new key blank to keep the saved key.","field-hint");apiKeyEnv.maxLength=128;advanced.prepend(advancedTitle);advanced.append(envHint);
  const clearKey=checkbox(keyEditor,"clear-api-key","Remove the saved API key"),keyActions=node("div",null,"security-policy-actions"),saveKey=button("Save API key"),cancelKey=button("Cancel");saveKey.type="submit";keyActions.append(cancelKey,saveKey);keyEditor.append(advanced,keyActions);keyForm.append(keyEditor);keyCard.append(keyTitle,keySummary,keyForm);
  const verificationCard=node("section",null,"settings-group abuse-verification-card"),verificationTitle=node("h3","Webmaster verification"),verificationForm=node("form"),verificationToken=field(verificationForm,"verification-token","Webmaster verification token"),verification=node("p","Copy the token from AbuseIPDB Webmaster Settings. The server publishes it at /abuseipdb-verification.html; finish verification on AbuseIPDB.","field-hint"),verificationActions=node("div",null,"security-policy-actions"),saveVerification=button("Save verification token");verificationForm.id="abuse-verification-form";verificationToken.maxLength=200;verificationToken.spellcheck=false;saveVerification.type="submit";verificationActions.append(saveVerification);verificationForm.append(verification,verificationActions);verificationCard.append(verificationTitle,verificationForm);credentials.append(keyCard,verificationCard);
  const settings=node("form",null,"settings-group abuse-settings"),policyTitle=node("h3","AbuseIPDB security policy"),policyHint=node("p","Automatic checks run after a failed sign-in. IP allowlists are respected. Reports include local failure counts and protocol, without account names or passwords.","field-hint"),policyGrid=node("div",null,"security-policy-grid");
  settings.id="abuse-policy-form";fields.enabled=checkbox(settings,"enabled","Enable AbuseIPDB");fields.auto_ban=checkbox(settings,"auto-ban","Automatically block IPs with high abuse confidence");fields.auto_report=checkbox(settings,"auto-report","Automatically report repeated failed sign-ins");
  fields.blacklist_enabled=checkbox(settings,"blacklist-enabled","Use the confidence-100 blacklist for automatic blocking");
  for(const [key,label,min,max] of [["score_threshold","Minimum abuse confidence (%)",1,100],["min_reports","Minimum reputation reports",1,1000000]])fields[key]=field(policyGrid,key,label,{type:"number",min,max,required:true});
  const durationFields={ban_seconds:durationField(policyGrid,"ban_seconds","Reputation block duration",1,604800),max_age_days:durationField(policyGrid,"max_age_days","Report lookback",1,365,{days:true}),cache_seconds:durationField(policyGrid,"cache_seconds","Reputation cache duration",60,86400)};
  durationFields.blacklist_refresh_seconds=durationField(policyGrid,"blacklist_refresh_seconds","Blacklist refresh interval",3600,604800);
  for(const [key,label] of [["automatic_check_budget","Automatic check requests per UTC day"],["automatic_report_budget","Automatic reports per UTC day"],["automatic_blacklist_budget","Automatic blacklist requests per UTC day"]])fields[key]=field(policyGrid,key,label,{type:"number",min:0,max:1000000,required:true});
  fields.report_threshold=field(policyGrid,"report_threshold","Local failed sign-ins before reporting",{type:"number",min:2,max:10000,required:true});durationFields.report_cooldown_seconds=durationField(policyGrid,"report_cooldown_seconds","Report cooldown per IP",900,604800);
  fields.report_categories=field(policyGrid,"report_categories","Report categories (comma-separated IDs)",{required:true});
  const reportHint=node("p","Category 18 is brute force. Automatic reporting shares the source IP and observed failure evidence with AbuseIPDB.","field-hint"),save=button("Save AbuseIPDB policy"),settingsActions=node("div",null,"security-policy-actions");save.type="submit";settingsActions.append(save);settings.prepend(policyTitle,policyHint);settings.append(policyGrid,reportHint,settingsActions);
  const plan=node("section",null,"settings-group abuse-automation-plan"),planTitle=node("h3","Automatic request plan"),planHint=node("p","Standard account defaults: blacklist every 6 hours, up to 4 of 5 daily requests including capacity probes; automatic checks and reports stop at 800 of 1,000. Manual requests also count toward these automation budgets.","field-hint"),sourceHint=node("p","Blacklist blocking uses membership in the provider's confidence-100 list. The minimum report count applies to individual IP checks, because blacklist responses do not include report counts.","field-hint"),reserveHint=node("p","Automatic requests preserve at least 20% of the observed allowance. Explicit manual tools may use the reserve. Local reservations are tracked across restarts and key changes; they are separate from AbuseIPDB's actual usage.","field-hint"),planScroll=node("div",null,"table-scroll"),planTable=node("table"),planHead=node("thead"),planHeader=node("tr"),planBody=node("tbody"),scheduleStatus=node("p",null,"field-hint");scheduleStatus.setAttribute("role","status");scheduleStatus.setAttribute("aria-live","polite");
  for(const key of ["Endpoint","Automatic daily budget","Locally reserved today","Automatic budget left"]){const th=node("th",key);th.scope="col";planHeader.append(th);}planHead.append(planHeader);planTable.append(planHead,planBody);planScroll.append(planTable);plan.append(planTitle,planHint,sourceHint,reserveHint,planScroll,scheduleStatus);
  const capacity=node("section",null,"abuse-capacity"),capacityTitle=node("h3","API usage and capacity"),capacityHint=node("p","Saving an API key checks capacity with one request to each read endpoint: check, reports, blacklist and check-block. Report, bulk-report and clear-address quotas appear after a real operation.","field-hint"),scroll=node("div",null,"table-scroll"),table=node("table"),thead=node("thead"),head=node("tr"),tbody=node("tbody");
  for(const label of ["Endpoint","Usage / capacity","Utilization","Quota resets"]){const th=node("th",label);th.scope="col";head.append(th);}thead.append(head);table.append(thead,tbody);scroll.append(table);const quotaStatus=node("p",null,"field-hint abuse-quota-status");quotaStatus.setAttribute("role","status");quotaStatus.setAttribute("aria-live","polite");const refreshCapacityButton=button("Refresh capacity");capacity.append(capacityTitle,capacityHint,refreshCapacityButton,quotaStatus,scroll);
  const tools=node("section",null,"settings-group abuse-tools"),toolsTitle=node("h3","IP reputation tools"),toolForm=node("form"),selectorLabel=node("label","Endpoint"),selector=node("select"),toolFields=node("div",null,"security-policy-grid"),toolHint=node("p",null,"field-hint"),run=button("Run AbuseIPDB request"),result=node("pre",null,"abuse-result"),summary=node("p",null,"abuse-summary");
  toolForm.id="abuse-tool-form";selector.id="abuse-endpoint";selectorLabel.htmlFor=selector.id;run.type="submit";result.hidden=true;result.tabIndex=0;summary.setAttribute("role","status");
  const endpoints=["check","reports","blacklist","check-block","report","bulk-report","bulk-check","clear-address"];
  endpoints.forEach(name=>{const option=node("option");option.value=name;option.textContent=name;selector.append(option);});selector.value="check";
  toolForm.append(selectorLabel,selector,toolHint,toolFields,run);tools.append(toolsTitle,toolForm,summary,result);root.append(intro,error,status,credentials,settings,plan,capacity,tools);
  const baseControlCount=controls.length,baseLabelCount=labels.length,baseDurationCount=durations.length;
  let toolInputs={},toolDurations={},toolNodes=[],csvUpload=null,toolHintKey="";
  function toolField(key,label,options){const input=field(toolFields,"tool-"+key,label,options);toolInputs[key]=input;toolNodes.push(input);return input;}
  function toolRender(){
    controls.splice(baseControlCount);labels.splice(baseLabelCount);durations.splice(baseDurationCount);toolFields.replaceChildren();toolNodes=[];toolInputs={};toolDurations={};csvUpload=null;summary.textContent="";result.textContent="";result.hidden=true;
    const name=selector.value;
    if(["check","reports","clear-address"].includes(name))toolField("ipAddress","IP address",{required:true});
    if(["check","reports","check-block","bulk-check"].includes(name)){const duration=durationField(toolFields,"tool-maxAgeInDays","Report lookback",1,365,{days:true});duration.set(30);toolInputs.maxAgeInDays=duration.input;toolDurations.maxAgeInDays=duration;}
    if(name==="check")toolInputs.verbose=checkbox(toolFields,"tool-verbose","Include report details");
    if(name==="reports"){toolField("page","Page",{type:"number",min:1,max:1000000,value:1,required:true});toolField("perPage","Reports per page",{type:"number",min:1,max:100,value:25,required:true});}
    if(name==="blacklist"){toolField("confidenceMinimum","Minimum abuse confidence (%)",{type:"number",min:25,max:100,value:100,required:true});toolField("limit","Maximum IPs",{type:"number",min:1,max:10000,value:100,required:true});}
    if(name==="check-block")toolField("network","Network (CIDR)",{required:true});
    if(name==="report"){toolField("ip","IP address",{required:true});toolField("categories","Report categories (comma-separated IDs)",{value:"18",required:true});const comment=toolField("comment","Observed abuse evidence",{type:"textarea",required:true});comment.maxLength=1024;}
    if(name==="bulk-check"){const ips=toolField("ips","IP addresses (one per line)",{type:"textarea",required:true});ips.rows=5;}
    if(name==="bulk-report"){
      const reports=toolField("reports","Report CSV",{type:"textarea",required:true});reports.rows=6;reports.placeholder='IP,Categories,ReportDate,Comment\n203.0.113.1,18,2026-10-25T12:00:00Z,"Observed repeated failed sign-ins"';
      csvUpload=toolField("csv","Upload report CSV",{type:"file"});csvUpload.accept=".csv,text/csv";
      csvUpload.addEventListener("change",async()=>{const file=csvUpload.files?.[0];if(!file)return;if(file.size>1048576){failure(new Error(t("Use a CSV file of up to 1 MiB.")));return;}const selected=version;try{const text=await file.text();if(active&&selected===version&&selector.value==="bulk-report")reports.value=text;}catch{failure(new Error(t("Unable to read the CSV file.")));}});
    }
    const hints={"bulk-check":"Bulk checks use individual check requests (up to 20 IPs). Each IP consumes check capacity; no separate bulk-check allowance is assumed.","bulk-report":"Paste or upload CSV with IP, Categories, ReportDate and Comment columns. Quote categories containing commas. Submit only abuse you observed.","clear-address":"Remove your own reports for this IP from AbuseIPDB. This does not remove other users' reports or local IP blocks.",report:"Submit only abuse you observed. The IP, categories and comment are sent to AbuseIPDB."};
    toolHintKey=hints[name]||"Requests use the server's saved API key. Available capacity and access depend on your AbuseIPDB account.";toolHint.textContent=t(toolHintKey);update();
  }
  function categories(value){const parts=String(value).split(",").map(value=>value.trim());if(!parts.length||parts.some(value=>!/^\d+$/.test(value)||Number(value)<1||Number(value)>23))throw new Error(t("Use category IDs from 1 to 23, separated by commas."));return [...new Set(parts.map(Number))];}
  function parseCSV(text){
    const rows=[];let row=[],value="",quoted=false,closed=false;
    text=String(text).replace(/^\uFEFF/,"");
    for(let i=0;i<=text.length;i++){
      const c=text[i];
      if(quoted){if(c===undefined)throw new Error(t("The report CSV has an unclosed quoted field."));if(c==='"'){if(text[i+1]==='"'){value+='"';i++;}else{quoted=false;closed=true;}}else value+=c;continue;}
      if(c==='"'&&!value&&!closed){quoted=true;continue;}
      if(c==='"')throw new Error(t("Check the report CSV columns and quoting."));
      if(c===","||c==="\n"||c==="\r"||c===undefined){row.push(value);value="";closed=false;if(c!==","){if(row.some(value=>value.trim()))rows.push(row);row=[];if(c==="\r"&&text[i+1]==="\n")i++;}continue;}
      if(closed)throw new Error(t("Check the report CSV columns and quoting."));value+=c;
    }
    const header=rows.shift()?.map(value=>value.trim().toLowerCase())||[],index=key=>header.indexOf(key);
    if(new Set(header).size!==header.length||["ip","categories","comment"].some(key=>index(key)<0)||!rows.length||rows.length>1000)throw new Error(t("Use 1 to 1,000 CSV rows with IP, Categories and Comment columns."));
    return rows.map(row=>{if(row.length!==header.length)throw new Error(t("Check the report CSV columns and quoting."));const report={ip:row[index("ip")].trim(),categories:categories(row[index("categories")]),comment:row[index("comment")]};const date=index("reportdate")>=0?row[index("reportdate")].trim():"";if(date)report.timestamp=date;return report;});
  }
  function readSettings(){const value={};for(const [key,input] of Object.entries(fields))value[key]=input.type==="checkbox"?input.checked:input.type==="number"?Number(input.value):key==="report_categories"?categories(input.value):input.value.trim();for(const [key,duration] of Object.entries(durationFields))value[key]=duration.read();return value;}
  function keyView(){keyEditor.hidden=!editingKey;modifyKey.hidden=editingKey||!snapshot?.api_key_configured;keyPlaceholder.placeholder=t(snapshot?.api_key_configured?"API key configured":"No API key configured");keyState.textContent=loaded?t(snapshot.api_key_configured?"The configured key is hidden. Choose Modify API key to replace it.":"Add an API key to connect AbuseIPDB."):"";cancelKey.hidden=!snapshot?.api_key_configured;}
  function update(){controls.forEach(input=>input.disabled=!loaded||busy);selector.disabled=!loaded||busy;refreshButton.disabled=busy;for(const action of [save,saveKey,cancelKey,modifyKey,saveVerification])action.disabled=!loaded||busy;refreshCapacityButton.disabled=!loaded||busy||!snapshot?.api_key_configured;run.disabled=!loaded||busy||!snapshot?.api_key_configured||!snapshot?.settings.enabled;keyView();}
  function failure(problem){if(!active)return;error.textContent=problem.message;error.hidden=false;}
  function renderQuotas(){
    tbody.replaceChildren();for(const endpoint of endpoints){const q=quotas.find(item=>item.endpoint===endpoint)||{},row=node("tr"),name=node("td"),usage=node("td"),utilization=node("td"),reset=node("td");name.textContent=endpoint;
      if(endpoint==="bulk-check"&&q.supported===false){usage.textContent=t("Uses check capacity");utilization.textContent=t("Individual checks");}
      else{usage.textContent=Number.isFinite(q.limit)&&Number.isFinite(q.used)?`${q.used.toLocaleString()} / ${q.limit.toLocaleString()}`:t("Unknown");if(Number.isFinite(q.limit)&&q.limit>0&&Number.isFinite(q.used)){const percent=Math.max(0,Math.min(100,q.used/q.limit*100)),meter=node("progress"),caption=node("span");meter.max=100;meter.value=percent;meter.setAttribute("aria-label",endpoint+" "+t("Utilization"));caption.textContent=`${percent.toFixed(1)}%`;utilization.append(meter,caption);}else utilization.textContent="—";}
      reset.textContent=Number.isFinite(q.reset_at)?new Date(q.reset_at*1000).toLocaleString(PostPlusI18n.language):"—";row.append(name,usage,utilization,reset);tbody.append(row);
    }
  }
  function renderPlan(){
    planBody.replaceChildren();for(const endpoint of ["check","report","blacklist"]){const data=automation?.budgets?.[endpoint],row=node("tr");for(const value of [endpoint,data?.limit,data?.used,data?.remaining]){const cell=node("td");cell.textContent=typeof value==="string"?value:Number.isFinite(value)?value.toLocaleString():t("Unknown");row.append(cell);}planBody.append(row);}
    const list=automation?.blacklist;if(!snapshot?.settings.enabled||!snapshot?.settings.auto_ban||!snapshot?.settings.blacklist_enabled){scheduleStatus.textContent=t("Scheduled blacklist refresh waits until AbuseIPDB, automatic blocking and blacklist protection are enabled.");return;}
    const date=Number.isFinite(list?.next_refresh_at)&&list.next_refresh_at>0?new Date(list.next_refresh_at*1000).toLocaleString(PostPlusI18n.language):t("Pending");scheduleStatus.textContent=t("Cached blacklist IPs: {count} · Next refresh: {time}",{count:list?.cached_ips||0,time:date});if(automation?.storage_available===false)scheduleStatus.textContent=t("Automatic requests are paused because durable usage storage is unavailable.");
  }
  function fill(data,{section="all"}={}){
    automation=data.automation||automation;
    if(section==="quotas"){quotas=data.quotas||quotas;renderQuotas();renderPlan();update();return;}
    snapshot=data;revision=data.revision;quotas=data.quotas||quotas;loaded=true;
    if(section==="all"||section==="policy"){
      for(const [key,input] of Object.entries(fields)){const value=data.settings[key];if(input.type==="checkbox")input.checked=value===true;else input.value=Array.isArray(value)?value.join(","):String(value??"");}
      for(const [key,duration] of Object.entries(durationFields))duration.set(data.settings[key]);
    }
    if(section==="all"||section==="verification")verificationToken.value=data.settings.verification_token||"";
    if(section==="all"||section==="key"){apiKey.value="";apiKeyEnv.value=data.settings.api_key_env||"";clearKey.checked=false;editingKey=!data.api_key_configured;}
    renderQuotas();renderPlan();update();
  }
  async function refresh(){if(!active||busy)return;const current=++version;busy=true;error.hidden=true;status.textContent=t("Loading AbuseIPDB…");update();try{const data=await api("/api/admin/abuseipdb");if(!active||current!==version)return;fill(data);status.textContent=t("AbuseIPDB settings loaded.");}catch(problem){failure(problem);}finally{if(active&&current===version){busy=false;update();}}}
  async function saveSection(value,section,message,{refreshCapacity=false}={}){
    const current=++version;busy=true;error.hidden=true;update();
    try{
      const data=await api("/api/admin/abuseipdb/settings",{method:"PUT",body:{revision,settings:value}});if(!active||current!==version)return;
      fill(data,{section});status.textContent=t(message);notice(status.textContent);
      if(refreshCapacity&&data.api_key_configured)await fetchCapacity(current);
    }catch(problem){failure(problem);}finally{if(active&&current===version){busy=false;update();}}
  }
  async function fetchCapacity(current){
    quotaStatusKey="Fetching available capacity…";quotaStatus.textContent=t(quotaStatusKey);
    const messages={complete:"Available capacity refreshed.",partial:"Some capacity information is unavailable. Unobserved limits remain unknown.",failed:"Capacity refresh failed. Your saved API key is retained.",not_configured:"Configure an API key before refreshing capacity.",cooldown:"Capacity was refreshed recently. Try again later.",busy:"Capacity refresh is already running."};
    try{
      for(let attempt=0;attempt<6;attempt++){
        if(!active||current!==version)return;
        const refreshed=await api("/api/admin/abuseipdb/quotas/refresh",{method:"POST",body:{},timeoutMs:30000});if(!active||current!==version)return;
        fill(refreshed,{section:"quotas"});
        const refreshStatus=refreshed.quota_refresh?.status;
        quotaStatusKey=messages[refreshStatus]||"Some capacity information is unavailable. Unobserved limits remain unknown.";quotaStatus.textContent=t(quotaStatusKey);
        if(refreshStatus!=="busy"||attempt===5)return;
        // Busy means no external probe started. Retry locally for a bounded
        // interval so a key rotation can outlast an older in-flight request.
        await new Promise(resolve=>setTimeout(resolve,1000));
      }
    }catch(problem){if(!active||current!==version)return;if(problem.data?.quotas){quotas=problem.data.quotas;renderQuotas();}quotaStatusKey="Capacity refresh failed. Your saved API key is retained.";quotaStatus.textContent=t(quotaStatusKey);failure(problem);}
  }
  refreshCapacityButton.addEventListener("click",async()=>{if(refreshCapacityButton.disabled)return;const current=++version;busy=true;error.hidden=true;update();try{await fetchCapacity(current);}finally{if(active&&current===version){busy=false;update();}}});
  modifyKey.addEventListener("click",()=>{editingKey=true;apiKey.value="";clearKey.checked=false;update();});
  cancelKey.addEventListener("click",()=>{editingKey=false;apiKey.value="";apiKeyEnv.value=snapshot?.settings.api_key_env||"";clearKey.checked=false;update();});
  keyForm.addEventListener("submit",event=>{event.preventDefault();if(saveKey.disabled||!keyForm.reportValidity())return;if(apiKey.value.trim()&&clearKey.checked){failure(new Error(t("Enter a replacement key or remove the saved key, not both.")));return;}const value={api_key_env:apiKeyEnv.value.trim()};if(apiKey.value.trim())value.api_key=apiKey.value.trim();if(clearKey.checked)value.clear_api_key=true;return saveSection(value,"key","AbuseIPDB API key saved.",{refreshCapacity:true});});
  verificationForm.addEventListener("submit",event=>{event.preventDefault();if(saveVerification.disabled||!verificationForm.reportValidity())return;return saveSection({verification_token:verificationToken.value.trim()},"verification","Webmaster verification token saved.");});
  settings.addEventListener("submit",event=>{event.preventDefault();if(save.disabled)return;const valid=Object.values(durationFields).map(duration=>duration.validate()).every(Boolean);if(!valid||!settings.reportValidity()){settings.reportValidity();return;}let value;try{value=readSettings();}catch(problem){failure(problem);return;}return saveSection(value,"policy","AbuseIPDB policy saved. Changes apply immediately.");});
  toolForm.addEventListener("submit",async event=>{event.preventDefault();if(run.disabled)return;const valid=Object.values(toolDurations).map(duration=>duration.validate()).every(Boolean);if(!valid||!toolForm.reportValidity()){toolForm.reportValidity();return;}const endpoint=selector.value,body={};try{for(const [key,input] of Object.entries(toolInputs)){if(key==="csv")continue;body[key]=Object.hasOwn(toolDurations,key)?toolDurations[key].read():key==="categories"?categories(input.value):key==="reports"?parseCSV(input.value):key==="ips"?input.value.split(/[\s,]+/).filter(Boolean):input.type==="number"?Number(input.value):input.type==="checkbox"?input.checked:input.value.trim();}}catch(problem){failure(problem);return;}
    const current=++version;busy=true;error.hidden=true;result.hidden=true;summary.textContent=t("Requesting AbuseIPDB…");update();try{const data=await api("/api/admin/abuseipdb/"+endpoint,{method:"POST",body,timeoutMs:120000});if(!active||current!==version)return;quotas=data.quotas||quotas;renderQuotas();result.textContent=JSON.stringify(data.meta?{data:data.data,meta:data.meta}:data.data??data,null,2);result.hidden=false;const info=data.data;summary.textContent=endpoint==="check"&&info&&Number.isFinite(info.abuseConfidenceScore)?t("Abuse confidence: {score}% · Reports: {reports}",{score:info.abuseConfidenceScore,reports:info.totalReports??0}):data.meta?.incomplete?t("Partial batch: {completed} of {requested} IPs processed. Retry the remaining IPs.",{completed:data.meta.completed,requested:data.meta.requested}):t("AbuseIPDB request completed.");}catch(problem){if(active&&current===version){if(problem.data?.quotas){quotas=problem.data.quotas;renderQuotas();}failure(problem);summary.textContent="";}}finally{if(active&&current===version){busy=false;update();}}});
  fields.enabled.addEventListener("change",update);selector.addEventListener("change",toolRender);refreshButton.addEventListener("click",refresh);toolRender();update();
  return {refresh,translate(){labels.forEach(({e,key})=>e.textContent=t(key));toolHint.textContent=t(toolHintKey);renderQuotas();renderPlan();durations.forEach(duration=>duration.translate());keyPlaceholder.setAttribute("aria-label",t("Saved API key"));quotaStatus.textContent=quotaStatusKey?t(quotaStatusKey):"";keyView();},dispose(){active=false;version++;apiKey.value="";snapshot=null;automation=null;quotas=[];root.replaceChildren();}};
}};
