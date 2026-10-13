"use strict";
window.PostPlusVerificationCode = (() => {
  const t = (...args) => PostPlusI18n.t(...args);
  const codePattern = /^(?:[0-9]{4,8}|(?=[A-Za-z0-9]{6,10}$)(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9]+)$/;
  function create(root, {request, prefix="verification-code"} = {}) {
    let disposed=false, loadVersion=0, revision=0, current=null, timer=null, loading=false, error="", copied=false, selected=false;
    function node(tag,className) {const value=document.createElement(tag);if(className)value.className=className;return value;}
    root.replaceChildren();root.hidden=true;
    const header=node("div","verification-code-header"),title=node("h2"),copy=node("button","button secondary"),details=node("div","verification-code-details"),code=node("input","verification-code-value"),source=node("div","verification-code-source"),subject=node("p"),sender=node("p"),received=node("p"),status=node("p","verification-code-status");
    title.id=`${prefix}-title`;root.setAttribute("aria-labelledby",title.id);copy.id=`${prefix}-copy`;copy.type="button";code.id=`${prefix}-value`;code.type="text";code.readOnly=true;code.autocomplete="off";code.spellcheck=false;code.addEventListener("click",()=>code.select());status.setAttribute("role","status");status.setAttribute("aria-live","polite");
    header.append(title,copy);source.append(subject,sender,received);details.append(code,source);root.append(header,details,status);
    function clearTimer(){if(timer!==null)clearTimeout(timer);timer=null;}
    function render(){
      if(disposed)return;
      title.textContent=t("Latest verification code");copy.textContent=t("Copy code");code.setAttribute("aria-label",t("Verification code"));
      root.setAttribute("aria-busy",String(loading));details.hidden=!current;copy.hidden=!current;copy.disabled=!current;
      code.value=current?.code||"";
      subject.textContent=current?.subject||t("(No subject)");sender.textContent=current?.from||"";
      received.textContent=current?t("Received {time}",{time:new Date(current.received_at*1000).toLocaleString(PostPlusI18n.language,{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"})}):"";
      status.textContent=error||t(loading?"Checking recent inbox mail…":copied?"Verification code copied.":selected?"Code selected. Copy it with Ctrl+C or your device's copy command.":current?"From recent inbox mail. Copying does not mark it as read.":"No recent verification code.");
      status.classList.toggle("error",Boolean(error));
    }
    function accept(value){
      clearTimer();revision++;copied=selected=false;current=null;
      if(value?.found===true && typeof value.code==="string" && codePattern.test(value.code) &&
         Number.isFinite(value.received_at) && value.received_at>=0 && Number.isFinite(value.expires_at) && value.expires_at*1000>Date.now()) {
        current={code:value.code,message_id:String(value.message_id||""),from:String(value.from||"").slice(0,512),subject:String(value.subject||"").slice(0,1024),received_at:value.received_at,expires_at:value.expires_at};
        const record=current;
        timer=setTimeout(()=>{if(disposed||current!==record)return;current=null;revision++;copied=selected=false;timer=null;render();},Math.min(2147483647,Math.max(1,record.expires_at*1000-Date.now())));
      }
      render();
    }
    async function load(){
      if(disposed)return;const version=++loadVersion;loading=true;error="";copied=selected=false;revision++;root.hidden=false;render();
      try {const value=await request("/api/verification-code",{quiet:true});if(disposed||version!==loadVersion)return;loading=false;accept(value);}
      catch(failure){if(disposed||version!==loadVersion)return;loading=false;error=failure?.message||t("Unable to check recent verification codes.");accept(null);}
    }
    copy.addEventListener("click",async()=>{
      if(disposed||!current||current.expires_at*1000<=Date.now()){if(current)accept(null);return;}
      const version=revision,value=current.code;
      try {if(!navigator.clipboard?.writeText)throw new Error("clipboard_unavailable");await navigator.clipboard.writeText(value);if(disposed||version!==revision||current?.code!==value)return;copied=true;selected=false;}
      catch {if(disposed||version!==revision||current?.code!==value)return;code.focus();code.select();selected=true;copied=false;}
      render();
    });
    function reset(){loadVersion++;revision++;clearTimer();current=null;loading=false;error="";copied=selected=false;render();root.hidden=true;}
    render();
    return {load,reset,translate:render,dispose(){reset();disposed=true;root.replaceChildren();}};
  }
  return {create};
})();
