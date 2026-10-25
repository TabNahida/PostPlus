"use strict";
window.PostPlusAdminAbuseIPDB={mount(root,{api,notice=()=>{}}){
  const t=(...args)=>PostPlusI18n.t(...args),labels=[],fields={},controls=[];
  let active=true,version=0,loaded=false,busy=false,revision=null,snapshot=null,quotas=[];
  const node=(tag,key,className)=>{const e=document.createElement(tag);if(className)e.className=className;if(key){labels.push({e,key});e.textContent=t(key);}return e;};
  const button=key=>{const e=node("button",key,"button secondary");e.type="button";return e;};
  function field(parent,key,label,{type="text",min,max,value,required=false}={}){
    const wrap=node("div",null,"security-field"),caption=node("label",label),input=node(type==="textarea"?"textarea":"input");
    input.id="abuse-"+key;caption.htmlFor=input.id;if(type!=="textarea")input.type=type;input.required=required;
    if(min!==undefined)input.min=String(min);if(max!==undefined)input.max=String(max);if(value!==undefined)input.value=String(value);if(type==="number")input.step="1";
    wrap.append(caption,input);parent.append(wrap);controls.push(input);return input;
  }
  function checkbox(parent,key,label){const wrap=node("label",null,"checkbox-label"),input=node("input"),caption=node("span",label);input.type="checkbox";input.id="abuse-"+key;wrap.append(input,caption);parent.append(wrap);controls.push(input);return input;}
  root.replaceChildren();
  const intro=node("div",null,"section-heading"),copy=node("div"),title=node("h2","AbuseIPDB"),help=node("p","Check IP reputation, review API capacity, and act on abusive sign-in attempts.","muted"),refreshButton=button("Refresh AbuseIPDB");copy.append(title,help);intro.append(copy,refreshButton);
  const error=node("p",null,"form-error"),status=node("p",null,"muted");error.hidden=true;error.setAttribute("role","alert");status.setAttribute("role","status");status.setAttribute("aria-live","polite");
  const settings=node("form",null,"settings-group abuse-settings"),connection=node("h3","Connection and verification"),grid=node("div",null,"security-policy-grid");
  fields.enabled=checkbox(settings,"enabled","Enable AbuseIPDB");
  const apiKey=field(grid,"api-key","AbuseIPDB API key",{type:"password"});apiKey.autocomplete="new-password";apiKey.maxLength=512;
  fields.api_key_env=field(grid,"api-key-env","API key environment variable");fields.api_key_env.maxLength=128;
  const keyState=node("p",null,"field-hint"),clearKey=checkbox(settings,"clear-api-key","Remove the saved API key");
  fields.verification_token=field(grid,"verification-token","Webmaster verification token");fields.verification_token.maxLength=200;fields.verification_token.spellcheck=false;
  const verification=node("p","Copy the token from AbuseIPDB Webmaster Settings. The server publishes it at /abuseipdb-verification.html; finish verification on AbuseIPDB.","field-hint");
  const policyTitle=node("h3","AbuseIPDB security policy"),policyHint=node("p","Automatic checks run after a failed sign-in. IP allowlists are respected. Reports include local failure counts and protocol, without account names or passwords.","field-hint"),policyGrid=node("div",null,"security-policy-grid");
  fields.auto_ban=checkbox(settings,"auto-ban","Automatically block IPs with high abuse confidence");
  for(const [key,label,min,max] of [["score_threshold","Minimum abuse confidence (%)",1,100],["min_reports","Minimum reputation reports",1,1000000],["ban_seconds","Reputation block duration (seconds)",1,604800],["max_age_days","Report lookback (days)",1,365],["cache_seconds","Reputation cache (seconds)",60,86400],["report_threshold","Local failed sign-ins before reporting",2,10000],["report_cooldown_seconds","Report cooldown per IP (seconds)",900,604800]])fields[key]=field(policyGrid,key,label,{type:"number",min,max,required:true});
  fields.report_categories=field(policyGrid,"report_categories","Report categories (comma-separated IDs)",{required:true});
  fields.auto_report=checkbox(settings,"auto-report","Automatically report repeated failed sign-ins");
  const reportHint=node("p","Category 18 is brute force. Automatic reporting shares the source IP and observed failure evidence with AbuseIPDB.","field-hint"),save=button("Save AbuseIPDB settings"),settingsActions=node("div",null,"security-policy-actions");save.type="submit";settingsActions.append(save);
  settings.append(connection,grid,keyState,clearKey.parentElement||clearKey,verification,policyTitle,policyHint,fields.auto_ban.parentElement||fields.auto_ban,fields.auto_report.parentElement||fields.auto_report,policyGrid,reportHint,settingsActions);
  const capacity=node("section",null,"abuse-capacity"),capacityTitle=node("h3","API usage and capacity"),capacityHint=node("p","Limits come from AbuseIPDB response headers after each request. Unknown means no limit has been observed. Refreshing this panel does not consume API requests.","field-hint"),scroll=node("div",null,"table-scroll"),table=node("table"),thead=node("thead"),head=node("tr"),tbody=node("tbody");
  for(const label of ["Endpoint","Usage / capacity","Utilization","Quota resets"]){const th=node("th",label);th.scope="col";head.append(th);}thead.append(head);table.append(thead,tbody);scroll.append(table);capacity.append(capacityTitle,capacityHint,scroll);
  const tools=node("section",null,"settings-group abuse-tools"),toolsTitle=node("h3","IP reputation tools"),toolForm=node("form"),selectorLabel=node("label","Endpoint"),selector=node("select"),toolFields=node("div",null,"security-policy-grid"),toolHint=node("p",null,"field-hint"),run=button("Run AbuseIPDB request"),result=node("pre",null,"abuse-result"),summary=node("p",null,"abuse-summary");
  selector.id="abuse-endpoint";selectorLabel.htmlFor=selector.id;run.type="submit";result.hidden=true;result.tabIndex=0;summary.setAttribute("role","status");
  const endpoints=["check","reports","blacklist","check-block","report","bulk-report","bulk-check","clear-address"];
  endpoints.forEach(name=>{const option=node("option");option.value=name;option.textContent=name;selector.append(option);});selector.value="check";
  toolForm.append(selectorLabel,selector,toolHint,toolFields,run);tools.append(toolsTitle,toolForm,summary,result);root.append(intro,error,status,settings,capacity,tools);
  const baseControlCount=controls.length,baseLabelCount=labels.length;
  let toolInputs={},toolNodes=[],csvUpload=null,toolHintKey="";
  function toolField(key,label,options){const input=field(toolFields,"tool-"+key,label,options);toolInputs[key]=input;toolNodes.push(input);return input;}
  function toolRender(){
    controls.splice(baseControlCount);labels.splice(baseLabelCount);toolFields.replaceChildren();toolNodes=[];toolInputs={};csvUpload=null;summary.textContent="";result.textContent="";result.hidden=true;
    const name=selector.value;
    if(["check","reports","clear-address"].includes(name))toolField("ipAddress","IP address",{required:true});
    if(["check","reports","check-block","bulk-check"].includes(name))toolField("maxAgeInDays","Report lookback (days)",{type:"number",min:1,max:365,value:30,required:true});
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
  function readSettings(){const value={};for(const [key,input] of Object.entries(fields))value[key]=input.type==="checkbox"?input.checked:input.type==="number"?Number(input.value):key==="report_categories"?categories(input.value):input.value.trim();return value;}
  function update(){controls.forEach(input=>input.disabled=!loaded||busy);selector.disabled=!loaded||busy;refreshButton.disabled=busy;save.disabled=!loaded||busy;run.disabled=!loaded||busy||!snapshot?.api_key_configured||!fields.enabled.checked;}
  function failure(problem){if(!active)return;error.textContent=problem.message;error.hidden=false;}
  function renderQuotas(){
    tbody.replaceChildren();for(const endpoint of endpoints){const q=quotas.find(item=>item.endpoint===endpoint)||{},row=node("tr"),name=node("td"),usage=node("td"),utilization=node("td"),reset=node("td");name.textContent=endpoint;
      if(endpoint==="bulk-check"&&q.supported===false){usage.textContent=t("Uses check capacity");utilization.textContent=t("Individual checks");}
      else{usage.textContent=Number.isFinite(q.limit)&&Number.isFinite(q.used)?`${q.used.toLocaleString()} / ${q.limit.toLocaleString()}`:t("Unknown");if(Number.isFinite(q.limit)&&q.limit>0&&Number.isFinite(q.used)){const percent=Math.max(0,Math.min(100,q.used/q.limit*100)),meter=node("progress"),caption=node("span");meter.max=100;meter.value=percent;meter.setAttribute("aria-label",endpoint+" "+t("Utilization"));caption.textContent=`${percent.toFixed(1)}%`;utilization.append(meter,caption);}else utilization.textContent="—";}
      reset.textContent=Number.isFinite(q.reset_at)?new Date(q.reset_at*1000).toLocaleString(PostPlusI18n.language):"—";row.append(name,usage,utilization,reset);tbody.append(row);
    }
  }
  function fill(data){snapshot=data;revision=data.revision;for(const [key,input] of Object.entries(fields)){const value=data.settings[key];if(input.type==="checkbox")input.checked=value===true;else input.value=Array.isArray(value)?value.join(","):String(value??"");}apiKey.value="";clearKey.checked=false;keyState.textContent=t(data.api_key_configured?"An API key is configured. Leave the key field blank to keep it.":"No API key is configured. Enter a key or configure the environment variable on the server.");quotas=data.quotas||[];loaded=true;renderQuotas();update();}
  async function refresh(){if(!active||busy)return;const current=++version;busy=true;error.hidden=true;status.textContent=t("Loading AbuseIPDB…");update();try{const data=await api("/api/admin/abuseipdb");if(!active||current!==version)return;fill(data);status.textContent=t("AbuseIPDB settings loaded.");}catch(problem){failure(problem);}finally{if(active&&current===version){busy=false;update();}}}
  settings.addEventListener("submit",async event=>{event.preventDefault();if(save.disabled||!settings.reportValidity())return;let value;try{value=readSettings();}catch(problem){failure(problem);return;}if(apiKey.value.trim())value.api_key=apiKey.value.trim();if(clearKey.checked)value.clear_api_key=true;const current=++version;busy=true;error.hidden=true;update();try{const data=await api("/api/admin/abuseipdb/settings",{method:"PUT",body:{revision,settings:value}});if(!active||current!==version)return;apiKey.value="";fill(data);status.textContent=t("AbuseIPDB settings saved. Policy changes apply immediately.");notice(status.textContent);}catch(problem){failure(problem);}finally{if(active&&current===version){busy=false;update();}}});
  toolForm.addEventListener("submit",async event=>{event.preventDefault();if(run.disabled||!toolForm.reportValidity())return;const endpoint=selector.value,body={};try{for(const [key,input] of Object.entries(toolInputs)){if(key==="csv")continue;body[key]=key==="categories"?categories(input.value):key==="reports"?parseCSV(input.value):key==="ips"?input.value.split(/[\s,]+/).filter(Boolean):input.type==="number"?Number(input.value):input.type==="checkbox"?input.checked:input.value.trim();}}catch(problem){failure(problem);return;}
    const current=++version;busy=true;error.hidden=true;result.hidden=true;summary.textContent=t("Requesting AbuseIPDB…");update();try{const data=await api("/api/admin/abuseipdb/"+endpoint,{method:"POST",body,timeoutMs:120000});if(!active||current!==version)return;quotas=data.quotas||quotas;renderQuotas();result.textContent=JSON.stringify(data.meta?{data:data.data,meta:data.meta}:data.data??data,null,2);result.hidden=false;const info=data.data;summary.textContent=endpoint==="check"&&info&&Number.isFinite(info.abuseConfidenceScore)?t("Abuse confidence: {score}% · Reports: {reports}",{score:info.abuseConfidenceScore,reports:info.totalReports??0}):data.meta?.incomplete?t("Partial batch: {completed} of {requested} IPs processed. Retry the remaining IPs.",{completed:data.meta.completed,requested:data.meta.requested}):t("AbuseIPDB request completed.");}catch(problem){if(active&&current===version){if(problem.data?.quotas){quotas=problem.data.quotas;renderQuotas();}failure(problem);summary.textContent="";}}finally{if(active&&current===version){busy=false;update();}}});
  fields.enabled.addEventListener("change",update);selector.addEventListener("change",toolRender);refreshButton.addEventListener("click",refresh);toolRender();update();
  return {refresh,translate(){labels.forEach(({e,key})=>e.textContent=t(key));toolHint.textContent=t(toolHintKey);renderQuotas();keyState.textContent=loaded?t(snapshot.api_key_configured?"An API key is configured. Leave the key field blank to keep it.":"No API key is configured. Enter a key or configure the environment variable on the server."):"";},dispose(){active=false;version++;apiKey.value="";snapshot=null;quotas=[];root.replaceChildren();}};
}};
