"use strict";
window.PostPlusVerificationCode = (() => {
  const t = (...args) => PostPlusI18n.t(...args);
  const codePattern = /^(?:[0-9]{4,8}|(?=[A-Za-z0-9]{6,10}$)(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9]+)$/;
  function actionLink(value){
    if(typeof value?.url!=="string"||value.url.length>2048||/[\s\u0000-\u001f\u007f\\<>\"]/.test(value.url)||/%(?:00|0a|0d)/i.test(value.url))return null;
    try {const url=new URL(value.url);return ["https:","http:"].includes(url.protocol)&&url.hostname&&!url.username&&!url.password?url.href:null;}catch{return null;}
  }
  function create(root, {request, prefix="verification-code"} = {}) {
    let disposed=false, loadVersion=0, revision=0, current=null, timer=null, loading=false, error="", copied=false, selected=false, folder="INBOX";
    function node(tag,className) {const value=document.createElement(tag);if(className)value.className=className;return value;}
    root.replaceChildren();root.hidden=true;
    const header=node("div","verification-code-header"),title=node("h2"),copy=node("button","button secondary"),details=node("div","verification-code-details"),code=node("input","verification-code-value"),source=node("div","verification-code-source"),subject=node("p"),sender=node("p"),received=node("p"),status=node("p","verification-code-status"),action=node("div","verification-link"),open=node("a","button secondary"),destination=node("p","verification-link-url"),notice=node("p","verification-link-notice");
    title.id=`${prefix}-title`;root.setAttribute("aria-labelledby",title.id);copy.id=`${prefix}-copy`;copy.type="button";code.id=`${prefix}-value`;code.type="text";code.readOnly=true;code.autocomplete="off";code.spellcheck=false;code.addEventListener("click",()=>code.select());status.setAttribute("role","status");status.setAttribute("aria-live","polite");
    open.id=`${prefix}-link`;open.target="_blank";open.rel="noopener noreferrer";open.referrerPolicy="no-referrer";destination.id=`${prefix}-destination`;open.setAttribute("aria-describedby",destination.id);action.append(open,destination,notice);
    header.append(title,copy);source.append(subject,sender,received);details.append(code,source,action);root.append(header,details,status);
    function clearTimer(){if(timer!==null)clearTimeout(timer);timer=null;}
    function render(){
      if(disposed)return;
      title.textContent=t("Latest verification code or link");copy.textContent=t("Copy code");code.setAttribute("aria-label",t("Verification code"));
      root.setAttribute("aria-busy",String(loading));details.hidden=!current;copy.hidden=!current?.code;copy.disabled=!current?.code;code.hidden=!current?.code;
      code.value=current?.code||"";
      action.hidden=!current?.link;open.textContent=t("Open verification link");destination.textContent=current?.link||"";notice.textContent=t("Check the sender and destination before opening.");
      if(current?.link)open.setAttribute("href",current.link);else open.removeAttribute("href");
      subject.textContent=current?.subject||t("(No subject)");sender.textContent=current?.from||"";
      received.textContent=current?t("Received {time}",{time:new Date(current.received_at*1000).toLocaleString(PostPlusI18n.language,{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"})}):"";
      status.textContent=error||(loading?t("Checking recent mail…"):copied?t("Verification code copied."):selected?t("Code selected. Copy it with Ctrl+C or your device's copy command."):current?t("From recent {folder} mail. Copying does not mark it as read.",{folder:t(folder==="Trash"?"Trash":"Inbox")}):t("No recent verification code or link."));
      status.classList.toggle("error",Boolean(error));
    }
    function accept(value){
      clearTimer();revision++;copied=selected=false;current=null;
      const candidateCode=typeof value?.code==="string"&&codePattern.test(value.code)?value.code:"",candidateLink=actionLink(value?.link);
      if(value?.found===true && (candidateCode||candidateLink) &&
         Number.isFinite(value.received_at) && value.received_at>=0 && Number.isFinite(value.expires_at) && value.expires_at*1000>Date.now()) {
        current={code:candidateCode,link:candidateLink,message_id:String(value.message_id||""),from:String(value.from||"").slice(0,512),subject:String(value.subject||"").slice(0,1024),received_at:value.received_at,expires_at:value.expires_at};
        const record=current;
        timer=setTimeout(()=>{if(disposed||current!==record)return;current=null;revision++;copied=selected=false;timer=null;render();},Math.min(2147483647,Math.max(1,record.expires_at*1000-Date.now())));
      }
      render();
    }
    async function load(selectedFolder="INBOX"){
      if(disposed)return;
      if(!["INBOX","Trash"].includes(selectedFolder)){reset();return;}
      if(selectedFolder!==folder){reset();folder=selectedFolder;}
      const version=++loadVersion;loading=true;error="";copied=selected=false;revision++;root.hidden=false;render();
      try {const value=await request(`/api/verification-code?folder=${encodeURIComponent(folder)}&include_links=true`,{quiet:true});if(disposed||version!==loadVersion)return;loading=false;accept(value);}
      catch(failure){if(disposed||version!==loadVersion)return;loading=false;error=failure?.message||t("Unable to check recent verification codes.");accept(null);}
    }
    copy.addEventListener("click",async()=>{
      if(disposed||!current?.code||current.expires_at*1000<=Date.now()){if(current?.expires_at*1000<=Date.now())accept(null);return;}
      const version=revision,value=current.code;
      try {if(!navigator.clipboard?.writeText)throw new Error("clipboard_unavailable");await navigator.clipboard.writeText(value);if(disposed||version!==revision||current?.code!==value)return;copied=true;selected=false;}
      catch {if(disposed||version!==revision||current?.code!==value)return;code.focus();code.select();selected=true;copied=false;}
      render();
    });
    open.addEventListener("click",event=>{if(disposed||!current?.link||current.expires_at*1000<=Date.now()){event.preventDefault();accept(null);}});
    function reset(){loadVersion++;revision++;clearTimer();current=null;loading=false;error="";copied=selected=false;render();root.hidden=true;}
    render();
    return {load,reset,translate:render,dispose(){reset();disposed=true;root.replaceChildren();}};
  }
  return {create};
})();
