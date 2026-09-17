"use strict";
// Generated dialog behavior; no browser dependencies, network, or native services.
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const vm=require("node:vm");
const source=fs.readFileSync(path.join(__dirname,"../web/preferences.js"),"utf8");
function fixture(portal) {
  const events=new Map(),stored=new Map();
  class Element {
    constructor(tag){this.tagName=tag;this.attributes={};this.dataset={};this.children=[];this.events=new Map();this.hidden=false;this.value="";}
    setAttribute(name,value){this.attributes[name]=String(value);if(name==="id")this.id=value;if(name==="type")this.type=value;if(name.startsWith("data-"))this.dataset[name.slice(5).replace(/-([a-z])/g,(_,letter)=>letter.toUpperCase())]=value;}
    removeAttribute(name){delete this.attributes[name];}
    append(...children){for(const child of children){if(child.parent)child.parent.children=child.parent.children.filter(item=>item!==child);child.parent=this;this.children.push(child);}}
    addEventListener(type,callback){this.events.set(type,callback);}
    fire(type){this.events.get(type)?.({target:this});}
    querySelectorAll(selector){return descendants(this).slice(1).filter(item=>selector.split(",").some(value=>matches(item,value.trim())));}
    querySelector(selector){return this.querySelectorAll(selector)[0] || null;}
    showModal(){this.open=true;}
    close(){this.open=false;}
  }
  function descendants(node){return [node,...node.children.flatMap(descendants)];}
  function matches(node,selector){if(selector.startsWith("#"))return node.id===selector.slice(1);if(selector.startsWith("["))return Object.hasOwn(node.attributes,selector.slice(1,-1));return node.tagName===selector;}
  const html=new Element("html"),body=new Element("body");html.dataset.portal=portal;html.append(body);
  const button=new Element("button");button.setAttribute("data-open-preferences","");body.append(button);
  const compose=new Element("textarea");compose.id="compose-text";body.append(compose);
  let policy;
  if(portal==="admin"){policy=new Element("details");policy.id="password-policy-panel";body.append(policy);}
  const document={documentElement:html,body,createElement:tag=>new Element(tag),getElementById:id=>descendants(html).find(item=>item.id===id),
    querySelectorAll:selector=>html.querySelectorAll(selector),querySelector:selector=>html.querySelector(selector),
    addEventListener(name,callback){if(!events.has(name))events.set(name,[]);events.get(name).push(callback);}};
  const media={matches:false,addEventListener(){}};
  const window={matchMedia:()=>media,addEventListener(){}};
  const i18n={language:"en",t:key=>key,apply(){},setLanguage(value){this.language=value;for(const callback of events.get("postplus:language") || [])callback();}};
  const sandbox={window,document,PostPlusI18n:i18n,localStorage:{getItem:key=>stored.get(key) ?? null,setItem:(key,value)=>stored.set(key,value)}};
  vm.runInNewContext(source,sandbox,{filename:"preferences.js"});
  const preferences=window.PostPlusPreferences;
  return {preferences,html,body,button,compose,policy,stored,i18n,id:document.getElementById,
    ready(){for(const callback of events.get("DOMContentLoaded") || [])callback();}};
}
const mail=fixture("webmail");mail.ready();mail.button.fire("click");
assert.equal(mail.id("preferences-dialog").open,true);
assert.equal(mail.id("preference-theme").value,"system");
assert.equal(mail.id("preference-language").value,"en");
mail.id("preference-language").value="zh-CN";mail.id("preference-language").fire("change");
assert.equal(mail.i18n.language,"zh-CN","The generated language selector changes the page language");
mail.id("preference-theme").value="dark";mail.id("preference-theme").fire("change");
assert.equal(mail.html.dataset.theme,"dark");
mail.id("preference-density").value="compact";mail.id("preference-density").fire("change");
assert.equal(mail.html.dataset.density,"compact");
mail.id("preference-reading").value="larger";mail.id("preference-reading").fire("change");
assert.equal(mail.html.dataset.reading,"larger");
mail.id("preference-spellcheck").checked=false;mail.id("preference-spellcheck").fire("change");
assert.equal(mail.compose.spellcheck,false,"The input preference updates the actual compose field");
assert.equal(JSON.parse(mail.stored.get("postplus.webmail.preferences")).spellcheck,false);
const admin=fixture("admin");admin.ready();
assert.equal(admin.policy.parent,admin.body,"Display settings must leave the account policy in its original account-management section");
assert.equal(admin.id("preference-spellcheck"),undefined,"Administration has no compose-only pretend preference");
assert.equal(admin.id("preferences-title").textContent,"Display settings");
const setup=fixture("setup");setup.ready();
assert.equal(setup.id("preference-reading"),undefined,"Setup does not expose a nonexistent message reader setting");
assert.equal(setup.id("preference-spellcheck"),undefined);
console.log("Preference dialog checks passed: generated controls, portal-specific options, live input settings, and separation of display/account settings.");
