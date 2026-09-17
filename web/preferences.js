"use strict";
// Run before styles load so a saved appearance does not flash the wrong theme.
window.PostPlusPreferences = (() => {
  const root = document.documentElement;
  const portal = root.dataset.portal || "webmail";
  const key = name => `postplus.${portal}.${name}`;
  const defaults = {theme:"system", density:"comfortable", reading:"standard", spellcheck:true};
  const choices = {theme:["system","light","dark"],density:["comfortable","compact"],reading:["standard","large","larger"]};
  function normalize(value) {
    const result = {...defaults};
    for (const [name, values] of Object.entries(choices)) if (values.includes(value?.[name])) result[name]=value[name];
    if (typeof value?.spellcheck === "boolean") result.spellcheck=value.spellcheck;
    return result;
  }
  let saved;
  try { saved=JSON.parse(localStorage.getItem(key("preferences"))); } catch { /* Defaults work without storage. */ }
  let values=normalize(saved);
  const system=window.matchMedia("(prefers-color-scheme: dark)");
  function apply() {
    root.dataset.theme=values.theme==="system" ? (system.matches ? "dark" : "light") : values.theme;
    root.dataset.appearance=values.theme;
    root.dataset.density=values.density;
    root.dataset.reading=values.reading;
    document.querySelectorAll("#compose-text, #compose-subject").forEach(input=>{input.spellcheck=values.spellcheck;});
  }
  function update(patch) {
    values=normalize({...values,...patch});
    try {localStorage.setItem(key("preferences"),JSON.stringify(values));} catch { /* Keep the current session usable. */ }
    apply();
  }
  system.addEventListener("change",()=>{if(values.theme==="system")apply();});
  apply();
  let closeNavigation=()=>{};
  document.addEventListener("DOMContentLoaded",()=>{
    const t=(...args)=>PostPlusI18n.t(...args);
    const node=(tag,attributes={},text)=>{const item=document.createElement(tag);for(const [name,value] of Object.entries(attributes))item.setAttribute(name,value);if(text){item.dataset.i18n=text;item.textContent=t(text);}return item;};
    const dialog=node("dialog",{id:"preferences-dialog","aria-labelledby":"preferences-title",class:"preferences-dialog"});
    const heading=node("header",{class:"dialog-header"}),title=node("h2",{id:"preferences-title"},"Display settings");
    const close=node("button",{type:"button",class:"icon-button","aria-label":t("Close display settings"),"data-i18n-aria-label":"Close display settings"});
    close.textContent="×";close.addEventListener("click",()=>dialog.close());heading.append(title,close);
    const body=node("div",{class:"dialog-body"});
    const description=node("p",{class:"field-hint"},"These preferences apply to this portal in this browser. Server settings are unchanged.");
    body.append(description);
    const controls={};
    function select(name,label,options) {
      const id=`preference-${name}`,wrap=node("div",{class:"preference-field"}),control=node("select",{id});
      for(const [value,text] of options)control.append(node("option",{value},text));
      wrap.append(node("label",{for:id},label),control);body.append(wrap);controls[name]=control;
      control.addEventListener("change",()=>name==="language" ? PostPlusI18n.setLanguage(control.value) : update({[name]:control.value}));
      return control;
    }
    select("language","Language",[["en","English"],["zh-CN","简体中文"]]);
    select("theme","Appearance",[["system","Follow system"],["light","Light"],["dark","Dark"]]);
    body.append(node("p",{class:"field-hint"},"Follow system changes appearance when your device switches between light and dark."));
    select("density","Layout density",[["comfortable","Comfortable"],["compact","Compact"]]);
    if(portal!=="setup")select("reading","Message text size",[["standard","Standard"],["large","Large"],["larger","Extra large"]]);
    if(portal==="webmail"){
      const label=node("label",{class:"checkbox-label",for:"preference-spellcheck"}),input=node("input",{id:"preference-spellcheck",type:"checkbox"});
      controls.spellcheck=input;input.addEventListener("change",()=>update({spellcheck:input.checked}));
      label.append(input,node("span",{},"Check spelling while composing"));body.append(label);
    }
    const footer=node("footer",{class:"dialog-footer"}),hint=node("span",{class:"muted",role:"status"},"Changes apply immediately."),done=node("button",{type:"button",class:"button primary"},"Done");
    done.addEventListener("click",()=>dialog.close());footer.append(hint,done);dialog.append(heading,body,footer);document.body.append(dialog);
    function sync(){for(const [name,control] of Object.entries(controls))if(name==="language")control.value=PostPlusI18n.language;else if(name==="spellcheck")control.checked=values.spellcheck;else control.value=values[name];}
    document.querySelectorAll("[data-open-preferences]").forEach(button=>button.addEventListener("click",()=>{closeNavigation();sync();dialog.showModal();}));
    document.addEventListener("postplus:language",()=>{PostPlusI18n.apply(dialog);sync();});
    const sidebar=document.querySelector(".sidebar"),toggle=document.getElementById("navigation-toggle"),workspace=document.querySelector(".workspace");
    if(sidebar && toggle && workspace){
      const narrow=window.matchMedia("(max-width: 900px)");
      const backdrop=node("button",{class:"navigation-backdrop",tabindex:"-1","aria-label":t("Close navigation"),"data-i18n-aria-label":"Close navigation"});backdrop.hidden=true;document.getElementById("app-screen").append(backdrop);
      let open=false;
      closeNavigation=()=>{
        open=false;root.removeAttribute("data-navigation");toggle.setAttribute("aria-expanded","false");backdrop.hidden=true;workspace.inert=false;
        sidebar.inert=narrow.matches;sidebar.removeAttribute("role");sidebar.removeAttribute("aria-modal");
        if(narrow.matches && sidebar.contains(document.activeElement))toggle.focus();
      };
      toggle.addEventListener("click",()=>{
        if(open){closeNavigation();return;}open=true;root.dataset.navigation="open";sidebar.inert=false;workspace.inert=true;
        sidebar.setAttribute("role","dialog");sidebar.setAttribute("aria-modal","true");toggle.setAttribute("aria-expanded","true");backdrop.hidden=false;
        sidebar.querySelector("[data-close-navigation]").focus();
      });
      backdrop.addEventListener("click",closeNavigation);
      sidebar.querySelectorAll("[data-close-navigation], [data-folder], [data-view], #compose-open, #logout").forEach(button=>button.addEventListener("click",()=>{if(open)closeNavigation();}));
      document.addEventListener("keydown",event=>{
        if(!open || dialog.open)return;
        if(event.key==="Escape"){event.preventDefault();closeNavigation();}
        if(event.key==="Tab"){
          const list=[...sidebar.querySelectorAll("a[href],button:not([disabled]),select")].filter(item=>!item.hidden && item.getClientRects().length);
          const first=list[0],last=list.at(-1);
          if(event.shiftKey && document.activeElement===first){event.preventDefault();last.focus();}
          else if(!event.shiftKey && document.activeElement===last){event.preventDefault();first.focus();}
        }
      });
      narrow.addEventListener("change",closeNavigation);closeNavigation();
    }
    window.addEventListener("storage",event=>{
      if(event.key===key("preferences")){try{values=normalize(JSON.parse(event.newValue));}catch{values={...defaults};}apply();sync();}
      if(event.key===key("language"))PostPlusI18n.setLanguage(event.newValue,false);
    });
    apply();sync();
  });
  return {key,update,get values(){return {...values};},closeNavigation(){closeNavigation();}};
})();
