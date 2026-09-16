"use strict";
// The same typed settings form is used during setup and in administration.
window.PostPlusSettings = (() => {
  const t = (...args) => PostPlusI18n.t(...args);
  const groups = {
    general:["General", "Your domain and the folders that make this server yours."],
    network:["Network", "Separate addresses and ports for administration, Webmail, and mail clients."],
    security:["Security", "Certificates, authentication, and connection protection."],
    limits:["Connection and message limits", "Choose sensible limits for mail clients and message uploads."],
    delivery:["Outgoing mail", "Connect a relay to send mail to other domains."],
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
    const prefix = options.prefix || "settings";
    root.replaceChildren();
    for (const [group, [title, description]] of Object.entries(groups)) {
      const fields = schema.filter(field => field.group === group && !options.exclude?.has(field.key));
      if (!fields.length) continue;
      const section = node("details", "settings-group");
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
          const choices = field.type === "boolean" ? [["true","Enabled"],["false","Disabled"]] : (field.options || []).map(value => [value,value]);
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
        if (field.readonly) wrapper.append(node("p","field-hint readonly-hint","Managed by the server. Change this in the configuration file while PostPlus is stopped."));
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
    function read({changedOnly = true} = {}) {
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
    return {read,translate:() => PostPlusI18n.apply(root),highlight:key => {const control = controls.get(key); if(control) reveal(control.input);},clearSecrets:() => controls.forEach(({field,input}) => {if(field.type === "password") input.value = "";})};
  }
  return {create};
})();
