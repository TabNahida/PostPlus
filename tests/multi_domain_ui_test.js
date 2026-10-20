"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),vm=require("node:vm");
class Element {
  constructor(tag="span"){this.tagName=tag.toUpperCase();this.children=[];this.value="";this.events={};this.attributes={};this.text="";}
  set textContent(value){this.text=String(value);this.children=[];}
  get textContent(){return this.text+this.children.map(child=>child.textContent).join("");}
  append(child){this.children.push(child);}
  setAttribute(key,value){this.attributes[key]=value;}
  addEventListener(name,callback){this.events[name]=callback;}
}
const sandbox={window:{},document:{createElement:tag=>new Element(tag)},PostPlusI18n:{t:key=>key}};
vm.runInNewContext(fs.readFileSync(path.join(__dirname,"../web/address.js"),"utf8"),sandbox);
const input=new Element("input"),suffix=new Element(),address=sandbox.window.PostPlusAddress.create(input,suffix);
address.setDomains(["Example.COM","EXAMPLE.NET","example.net"]);
let selector=suffix.children[0];
assert.equal(selector.tagName,"SELECT");assert.equal(selector.attributes["aria-label"],"Mail domain");
assert.equal(selector.children.length,2);assert.equal(selector.value,"example.com");
input.value="same";assert.equal(address.address(),"same@example.com");
selector.value="example.net";selector.events.change();assert.equal(address.address(),"same@example.net");
input.value=" SAME@Example.COM ";input.events.change();assert.equal(input.value,"SAME");assert.equal(selector.value,"example.com");assert.equal(address.address(),"same@example.com");
input.value="same@example.net";assert.equal(address.address(),"same@example.net");assert.equal(selector.value,"example.net");
input.value="same@other.example";assert.throws(()=>address.address(),/displayed domain/);
address.setAddress("legacy@removed.example");assert.equal(suffix.children.length,0);assert.equal(address.address(),"legacy@removed.example");assert.equal(input.readOnly,true);
address.setAddress();assert.equal(input.readOnly,false);assert.equal(suffix.children[0].value,"example.net");
address.setDomains(["example.com","example.org"]);assert.equal(suffix.children[0].value,"example.com");
for(const invalid of [[],["bad domain"],["user@example.com"],"example.net",[null]])assert.throws(()=>address.setDomains(invalid),/unreadable response/);
address.setDomains(Array.from({length:240},(_,index)=>`domain${index}.example`));assert.equal(suffix.children[0].children.length,240);input.value="user@domain239.example";assert.equal(address.address(),"user@domain239.example");
address.setDomain("localhost");assert.equal(suffix.children.length,0);assert.equal(suffix.textContent,"@localhost");
input.value="user";assert.equal(address.address(),"user@localhost");
address.setDraftDomain(" draft.example ");assert.equal(suffix.textContent,"@draft.example");assert.equal(address.address(),"user@draft.example");
const adminInput=new Element("input"),adminSuffix=new Element(),adminAddress=sandbox.window.PostPlusAddress.create(adminInput,adminSuffix,{allowFullAddress:true});
adminAddress.setDomain("example.com");adminInput.value="admin@removed.example";adminInput.events.input();assert.equal(adminSuffix.hidden,true);assert.equal(adminAddress.address(),"admin@removed.example","Retained administrators can sign in after their mailbox domain is removed");
adminInput.value="admin";adminInput.events.input();assert.equal(adminSuffix.hidden,false);assert.equal(adminAddress.address(),"admin@example.com");
adminInput.value="bad@@removed.example";assert.throws(()=>adminAddress.address(),/valid email address/);
console.log("PASS multi-domain suffix selection, full-address autofill, exact-domain isolation, fixed account identity and single-domain compatibility");
