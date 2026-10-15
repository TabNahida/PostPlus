"use strict";
window.PostPlusMailTools=(()=>{
  const t=(...args)=>PostPlusI18n.t(...args);
  function node(tag,cls,text){const value=document.createElement(tag);if(cls)value.className=cls;if(text!==undefined)value.textContent=text;return value;}
  function createSearch(root,{onChange}){
    const form=node("form","mail-search"),bar=node("div","mail-search-bar"),query=node("input"),submit=node("button","button secondary"),clear=node("button","button text-button"),details=node("details","mail-search-filters"),summary=node("summary"),fields=node("div","mail-filter-grid"),status=node("p","field-hint"),more=node("button","button secondary");
    query.type="search";query.maxLength=256;query.id="mail-search-query";submit.type="submit";clear.type="button";more.type="button";
    const controls={q:query};let active=false,next=null,filters={},disposed=false;
    function field(name,label,type="text",options){
      const wrap=node("label"),caption=node("span"),control=node(options?"select":"input");
      if(options)for(const [value,text]of options){const option=node("option","",t(text));option.value=value;control.append(option);}
      else {control.type=type;control.maxLength=256;}
      controls[name]=control;caption.dataset.label=label;wrap.append(caption,control);fields.append(wrap);return control;
    }
    field("scope","Search in","text",[["current","Current folder"],["all","All folders"]]);
    field("from","From");field("to","To");field("subject","Subject");field("after","After","date");field("before","Before","date");
    field("seen","Read status","text",[["","Any"],["false","Unread"],["true","Read"]]);
    field("has_attachment","Attachments","text",[["","Any"],["true","With attachments"],["false","Without attachments"]]);
    controls.scope.value="current";controls.seen.value="";controls.has_attachment.value="";
    status.setAttribute("role","status");status.hidden=true;more.hidden=true;
    bar.append(query,submit,clear);details.append(summary,fields);form.append(bar,details,status,more);root.append(form);
    function translate(){
      query.placeholder=t("Search mail");query.setAttribute("aria-label",t("Search mail"));submit.textContent=t("Search");clear.textContent=t("Clear search");summary.textContent=t("Search filters");more.textContent=t("Load more");
      for(const wrap of fields.children)wrap.children[0].textContent=t(wrap.children[0].dataset.label);
      for(const [name,labels]of Object.entries({scope:["Current folder","All folders"],seen:["Any","Unread","Read"],has_attachment:["Any","With attachments","Without attachments"]}))Array.from(controls[name].children).forEach((option,i)=>{option.textContent=t(labels[i]);});
    }
    function reset(){active=false;next=null;filters={};form.reset();query.value="";for(const [name,control]of Object.entries(controls))control.value=name==="scope"?"current":"";status.hidden=true;more.hidden=true;}
    form.addEventListener("submit",event=>{
      event.preventDefault();filters={};
      for(const [name,control]of Object.entries(controls)){const value=control.value.trim();if(!value)continue;if(name==="after"||name==="before"){const timestamp=Date.parse(value+"T00:00:00Z")/1000;if(Number.isFinite(timestamp))filters[name]=String(timestamp+(name==="before"?86400:0));}else filters[name]=value;}
      active=true;next=null;onChange(false);
    });
    clear.addEventListener("click",()=>{reset();onChange(false);});more.addEventListener("click",()=>{if(active&&next!==null)onChange(true);});
    translate();
    return {get active(){return active;},query(folder,append=false){const params=new URLSearchParams({...filters,folder:filters.scope==="all"?"all":folder,limit:"50",offset:String(append&&next!==null?next:0)});params.delete("scope");return "/api/messages/search?"+params;},show(data){if(disposed)return;next=data.has_more?(data.next_offset??((data.offset??0)+(data.limit??50))):null;more.hidden=next===null;status.hidden=false;status.textContent=data.indexing?t("Indexing existing mail…"):data.has_more?t("More matching messages are available."):t("Search complete");},busy(flag){submit.disabled=flag;more.disabled=flag;form.setAttribute("aria-busy",String(flag));},reset,translate,dispose(){disposed=true;root.replaceChildren();}};
  }
  function createDelivery(root,{request}){
    let version=0,timer=null,current=null,disposed=false;
    function reset(){version++;clearTimeout(timer);timer=null;current=null;root.replaceChildren();root.hidden=true;}
    function render(data){
      root.replaceChildren();root.hidden=false;const title=node("h3","",t("Delivery status"));root.append(title);
      const recipients=data.recipients||[];
      if(!recipients.length){root.append(node("p","field-hint",t("No delivery history is available for this message.")));return;}
      const list=node("ul","delivery-recipient-list");
      for(const item of recipients){
        const row=node("li","delivery-recipient"),heading=node("div","delivery-recipient-heading"),state=item.state||"queued";
        const labels={queued:"Queued",retrying:"Retrying",delivered:item.remote_accepted||["remote","remote_mta"].includes(item.delivery_scope)?"Accepted by recipient server":"Delivered to local mailbox",rejected:"Quarantined",failed:"Delivery failed"};
        const badge=node("span","delivery-state",t(Object.hasOwn(labels,state)?labels[state]:"Queued"));badge.dataset.state=state;
        heading.append(node("strong","",item.recipient),badge);row.append(heading);
        if(item.attempts)row.append(node("p","field-hint",t("Attempts: {count}",{count:item.attempts})));
        if(item.last_error||item.error)row.append(node("p","delivery-error",item.last_error||item.error));
        if(item.next_attempt&&state==="retrying")row.append(node("p","field-hint",t("Next attempt: {time}",{time:new Date(item.next_attempt*1000).toLocaleString(PostPlusI18n.language)})));
        const history=item.events||item.history||[];
        if(history.length){const details=node("details"),summary=node("summary","",t("Delivery history")),events=node("ul");for(const event of history){const line=node("li"),at=event.created_at||event.at;line.textContent=[at?new Date(at*1000).toLocaleString(PostPlusI18n.language):"",event.state?t(Object.hasOwn(labels,event.state)?labels[event.state]:event.state):"",event.error||event.detail||""].filter(Boolean).join(" · ");events.append(line);}details.append(summary,events);row.append(details);}
        list.append(row);
      }
      root.append(list,node("p","field-hint",t("Remote acceptance confirms handoff to the recipient server; it does not confirm inbox placement or reading.")));
    }
    async function load(id){
      reset();if(disposed||!id)return;const token=version;current=id;
      async function refresh(){
        try{const data=await request(`/api/messages/${encodeURIComponent(id)}/delivery-status`,{quiet:true});if(disposed||token!==version)return;render(data);if((data.recipients||[]).some(item=>["queued","retrying"].includes(item.state)))timer=setTimeout(refresh,10000);}
        catch(error){if(disposed||token!==version)return;root.hidden=false;root.replaceChildren(node("p","field-hint",error.message));}
      }
      await refresh();
    }
    root.hidden=true;return {load,reset,translate(){if(current)load(current);},dispose(){reset();disposed=true;}};
  }
  return {createSearch,createDelivery};
})();
