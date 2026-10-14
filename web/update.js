"use strict";
window.PostPlusUpdate = (() => {
  const t = (...args) => PostPlusI18n.t(...args);
  const activeStates = new Set(["pending_download","downloading","pending_apply","applying"]);
  const states = new Set(["idle",...activeStates,"staged","complete","failed"]);
  function create(root,{request,canChange=()=>true,onBusy=()=>{},adminUrl=()=>location.href,prefix="update"}={}) {
    let disposed=false,revision=0,timer=null,data={state:"idle",available:true},checking=false,action=false,started=0,problem="",reconnect=false;
    function node(tag,key,className){const item=document.createElement(tag);if(key)item.textContent=t(key);if(className)item.className=className;return item;}
    root.replaceChildren();
    const title=node("h3","Update PostPlus"),intro=node("p","Check the latest stable GitHub Release. Download its complete package and replace only changed modules after reviewing the affected services.","field-hint"),version=node("p",null,"field-hint"),status=node("p",null,"dns-prerequisite"),error=node("p",null,"form-error"),plan=node("div",null,"update-plan"),files=node("ul",null,"update-files"),services=node("p",null,"field-hint"),size=node("p",null,"field-hint"),actions=node("div",null,"update-actions"),check=node("button","Check for updates","button secondary"),stage=node("button","Download update package","button secondary"),apply=node("button","Apply prepared update","button primary"),retry=node("button","Refresh update status","button secondary"),open=node("a","Reopen administration ↗","button secondary"),release=node("a","View GitHub Release ↗","button secondary");
    status.id=`${prefix}-status`;status.setAttribute("role","status");status.setAttribute("aria-live","polite");error.setAttribute("role","alert");
    for(const [name,button] of Object.entries({check,stage,apply,retry})){button.type="button";button.id=`${prefix}-${name}`;}open.id=`${prefix}-open`;open.hidden=true;release.id=`${prefix}-release`;release.hidden=true;release.target="_blank";release.rel="noopener noreferrer";plan.append(services,size,files);actions.append(check,stage,apply,retry,release,open);root.append(title,intro,version,status,error,plan,actions);
    function busy(){return checking||action||!reconnect&&activeStates.has(data.state);}
    function current(){return data.state==="complete"&&target()?target():typeof data.current_version==="string"?data.current_version:"";}
    function target(){return typeof data.version==="string"?data.version:"";}
    function newer(){return data.state!=="complete"&&(data.update_available===true||data.update_available!==false&&Boolean(target()&&target()!==current()));}
    function safeData(value){
      if(!value||value.ok===false||value.state&&!states.has(value.state)||value.job_id&&(!/^[a-z0-9_-]{1,128}$/i.test(value.job_id))||value.version&&typeof value.version!=="string"||value.files&&!Array.isArray(value.files)||value.services&&!Array.isArray(value.services))throw new Error(t("The server returned an unreadable response."));
      return value;
    }
    function render(){
      if(disposed)return;
      const working=busy(),enabled=data.available!==false;onBusy(working);root.setAttribute("aria-busy",String(working));
      title.textContent=t("Update PostPlus");intro.textContent=t("Check the latest stable GitHub Release. Download its complete package and replace only changed modules after reviewing the affected services.");
      version.textContent=current()?t("Installed version: {version}",{version:current()}):"";
      let key="Check for a release when you are ready to update.";
      if(!enabled)key="Automatic updates are unavailable for this server. Install a supported release layout and restart the launcher.";
      else if(data.supported===false)key="This release does not support verified module updates. Open its GitHub Release and follow the manual upgrade instructions.";
      else if(checking)key="Checking the latest GitHub Release…";
      else if(reconnect)key="Update completion could not be confirmed. Reopen administration, sign in, and refresh the update status.";
      else if(data.state==="pending_download"||data.state==="downloading")key="Downloading and verifying the update package for {version}…";
      else if(data.state==="staged")key="Update {version} is prepared. Review the file and service list, then apply it.";
      else if(data.state==="pending_apply"||data.state==="applying")key=data.requires_launcher_restart?"Applying update {version}. The launcher will restart; administration may disconnect.":"Applying update {version}. Only affected services restart; administration may disconnect.";
      else if(data.state==="complete")key="Update {version} completed.";
      else if(data.state==="failed")key=data.rolled_back?"The update failed. Previous files and services were restored.":"The update failed. Review the server error and logs before retrying.";
      else if(newer())key="Release {version} is available. Download its package to prepare the changed modules.";
      else if(data.checked_at||target())key="PostPlus is up to date.";
      const detail=problem||(data.state==="failed"&&data.error?t("Server error: {error}",{error:data.error}):"");
      status.textContent=t(key,{version:target()});error.hidden=!detail;error.textContent=detail;
      const serviceNames=Array.isArray(data.services)?data.services.filter(value=>typeof value==="string"):[];
      services.textContent=serviceNames.length?t("Affected services: {services}",{services:serviceNames.join(", ")}):"";
      size.textContent=Number.isSafeInteger(data.download_bytes)&&data.download_bytes>=0?t("Package download: {bytes} bytes.",{bytes:data.download_bytes.toLocaleString()}):"";
      if(Number.isSafeInteger(data.changed_bytes)&&data.changed_bytes>=0)size.textContent+=" "+t("Changed modules: {bytes} bytes.",{bytes:data.changed_bytes.toLocaleString()});
      files.replaceChildren();for(const entry of (data.files || []).slice(0,128)){const path=typeof entry==="string"?entry:entry?.path||entry?.name;if(typeof path==="string")files.append(node("li",path));}
      plan.hidden=!serviceNames.length&&!files.children.length&&!size.textContent;
      check.textContent=t("Check for updates");stage.textContent=t("Download update package");apply.textContent=t("Apply prepared update");retry.textContent=t("Refresh update status");open.textContent=t("Reopen administration ↗");release.textContent=t("View GitHub Release ↗");
      check.disabled=!enabled||working;stage.hidden=data.supported===false||!newer()||data.state==="staged"||activeStates.has(data.state)||reconnect;stage.disabled=!enabled||working||!canChange();apply.hidden=data.state!=="staged"||reconnect;apply.disabled=working||!canChange();retry.hidden=!data.job_id&&!problem;retry.disabled=checking||action;open.hidden=!reconnect;
      release.hidden=typeof data.release_url!=="string"||!/^https:\/\/github\.com\/TabNahida\/PostPlus\/releases\/tag\/v[0-9]+\.[0-9]+\.[0-9]+$/.test(data.release_url);if(!release.hidden)release.href=data.release_url;
      if(reconnect){try{const url=new URL(adminUrl());if(!["http:","https:"].includes(url.protocol)||url.username||url.password)throw new Error();open.href=url.href;}catch{open.hidden=true;}}
    }
    function clearTimer(){if(timer!==null)clearTimeout(timer);timer=null;}
    function failure(error){return error?.data?.error? t("Server error: {error}",{error:String(error.data.error)}):error?.message || t("The request failed. Please try again.");}
    function schedule(){clearTimer();if(!disposed&&activeStates.has(data.state))timer=setTimeout(()=>poll(),1500);}
    async function poll(){
      if(disposed||!data.job_id)return;clearTimer();const expected=revision,id=data.job_id;
      try {const response=safeData(await request("/api/admin/update?job_id="+encodeURIComponent(id),{timeoutMs:5000}));if(disposed||expected!==revision)return;if(response.job_id&&response.job_id!==id)throw new Error(t("The server returned an unreadable response."));data={...data,...response};started=Date.now();reconnect=false;problem=data.state==="failed"&&data.error?t("Server error: {error}",{error:data.error}):"";}
      catch(error){if(disposed||expected!==revision)return;if(error?.status===401||Date.now()-started>=90000){reconnect=true;problem="";onBusy(false);render();return;}problem=failure(error);}
      render();schedule();
    }
    async function load(){
      if(disposed)return;clearTimer();const expected=++revision;checking=true;problem="";reconnect=false;render();
      try {const response=safeData(await request("/api/admin/update",{timeoutMs:5000}));if(disposed||expected!==revision)return;data={...data,...response};started=Date.now();}
      catch(error){if(disposed||expected!==revision)return;problem=failure(error);}
      finally{if(!disposed&&expected===revision){checking=false;render();schedule();}}
    }
    async function mutate(kind){
      if(disposed||busy()||!canChange()||kind==="stage"&&(!newer()||data.supported===false)||kind==="apply"&&data.state!=="staged")return;
      const expected=++revision;clearTimer();action=true;problem="";reconnect=false;render();
      try {const body=kind==="stage"?{version:target()}:{job_id:data.job_id};const response=safeData(await request("/api/admin/update/"+kind,{method:"POST",body,timeoutMs:15000}));if(disposed||expected!==revision)return;if(!response.job_id)throw new Error(t("The server returned an unreadable response."));data={...data,...response};started=Date.now();}
      catch(error){if(disposed||expected!==revision)return;problem=failure(error);if(kind==="apply"&&error?.status===401)reconnect=true;else if(kind==="apply"&&!error?.status){data.state="pending_apply";started=Date.now();}}
      finally{if(!disposed&&expected===revision){action=false;render();schedule();}}
    }
    check.addEventListener("click",async()=>{
      if(disposed||busy())return;const expected=++revision;clearTimer();checking=true;problem="";reconnect=false;render();
      try{const response=safeData(await request("/api/admin/update/check",{method:"POST",body:{},timeoutMs:15000}));if(disposed||expected!==revision)return;data={...data,...response,state:response.state||"idle",job_id:response.job_id||"",checked_at:response.checked_at||new Date().toISOString()};}
      catch(error){if(!disposed&&expected===revision)problem=failure(error);}
      finally{if(!disposed&&expected===revision){checking=false;render();schedule();}}
    });
    stage.addEventListener("click",()=>mutate("stage"));apply.addEventListener("click",()=>mutate("apply"));retry.addEventListener("click",()=>{if(checking||action)return;if(!data.job_id)return load();revision++;started=Date.now();reconnect=false;problem="";poll();});
    render();return {load,translate:render,dispose(){disposed=true;revision++;clearTimer();onBusy(false);root.replaceChildren();}};
  }
  return {create};
})();
