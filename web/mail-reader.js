"use strict";
// Mail markup is reconstructed from an inert document. No sender-owned node is
// inserted into the portal, and the rendered document has an opaque origin.
window.PostPlusMailReader = (() => {
  const htmlNamespace="http://www.w3.org/1999/xhtml";
  const allowed=new Set("a b blockquote br caption center code col colgroup dd del div dl dt em figcaption figure font h1 h2 h3 h4 h5 h6 hr i img li ol p pre s small span strong sub sup table tbody td th thead tfoot tr u ul wbr".split(" "));
  const discarded=new Set("script style iframe frame frameset object embed applet audio video source track form input textarea select option button base meta link noscript template svg math canvas".split(" "));
  const blocks=new Set("blockquote caption center dd div dl dt figcaption figure h1 h2 h3 h4 h5 h6 hr li ol p pre table tbody td th thead tfoot tr ul".split(" "));
  const voids=new Set(["br","col","hr","img","wbr"]);
  const safeStyles=new Set("color background background-color font font-family font-size font-weight font-style font-variant line-height letter-spacing word-spacing text-align text-decoration text-decoration-color text-decoration-line text-decoration-style text-indent text-transform white-space vertical-align border border-top border-right border-bottom border-left border-width border-style border-color border-top-width border-right-width border-bottom-width border-left-width border-top-style border-right-style border-bottom-style border-left-style border-top-color border-right-color border-bottom-color border-left-color border-radius border-collapse border-spacing margin margin-top margin-right margin-bottom margin-left padding padding-top padding-right padding-bottom padding-left width min-width max-width height min-height max-height box-sizing display table-layout list-style-type float clear overflow-wrap word-break".split(" "));
  const t=(...args)=>PostPlusI18n.t(...args);
  const string=value=>typeof value==="string"?value:"";
  const escape=value=>string(value).replace(/[&<>"']/g,char=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
  function bodySource(value) {
    const raw=string(value),separator=/\r?\n\r?\n/.exec(raw);
    if(!separator)return raw;
    // Strip only a complete top-level RFC 5322 header block. MIME part headers
    // and the encoded body stay byte-for-byte as received in this text view.
    const lines=raw.slice(0,separator.index).split(/\r?\n/);let headers=0;
    for(const line of lines){
      if(/^[ \t]/.test(line)){if(!headers)return raw;}
      else if(/^[\x21-\x39\x3b-\x7e]+:/.test(line))headers++;
      else return raw;
    }
    return headers?raw.slice(separator.index+separator[0].length):raw;
  }
  function safeUrl(value,image=false) {
    const raw=string(value).trim();
    if(!raw || /[\u0000-\u0020\u007f]/.test(raw))return "";
    try {
      const url=new URL(raw);
      if(url.username || url.password || !(image?["https:","http:"]:["https:","http:","mailto:"]).includes(url.protocol))return "";
      return url.href;
    } catch {return "";}
  }
  function raster(type,data) {
    type=string(type).trim().toLowerCase();data=string(data).replace(/[\t\r\n ]/g,"");
    if(!["image/png","image/jpeg","image/gif","image/webp"].includes(type) || data.length>8*1024*1024 || !data || data.length%4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(data))return "";
    let bytes;try {bytes=atob(data.slice(0,44));}catch{return "";}
    const valid=type==="image/png"?bytes.startsWith("\x89PNG\r\n\x1a\n"):type==="image/jpeg"?bytes.startsWith("\xff\xd8\xff"):type==="image/gif"?/^GIF8[79]a/.test(bytes):bytes.startsWith("RIFF")&&bytes.slice(8,12)==="WEBP";
    return valid?`data:${type};base64,${data}`:"";
  }
  function cid(value) {return string(value).trim().replace(/^<|>$/g,"");}
  function inlineStyle(style) {
    const result=[];
    for(let i=0;i<(style?.length || 0);i++) {
      const property=style.item(i).toLowerCase(),value=style.getPropertyValue(property).trim();
      // Only properties which cannot load a resource are retained. Reject
      // control syntax and functions used by legacy active CSS as well.
      if(!safeStyles.has(property) || !value || value.length>300 || /url\s*\(|image-set\s*\(|expression\s*\(|var\s*\(|@|[\\{}<>\u0000-\u001f\u007f]/i.test(value))continue;
      if(property==="display" && !["block","inline","inline-block","table","inline-table","table-row","table-cell","table-row-group","table-header-group","table-footer-group","table-column","table-column-group","list-item","none"].includes(value))continue;
      result.push(`${property}:${value}${style.getPropertyPriority?.(property)==="important"?"!important":""}`);
    }
    return result.join(";");
  }
  function stylesheet(source) {
    // A constructed sheet never enters a live document. @import and all other
    // resource-bearing/active rules are discarded; only inert declarations
    // and bounded media queries are reconstructed inside the opaque iframe.
    if(typeof CSSStyleSheet!=="function" || source.length>200000)return "";
    let sheet;try{sheet=new CSSStyleSheet();sheet.replaceSync(source);}catch{return "";}
    let count=0;
    function rules(entries,depth=0){
      if(depth>4)return "";
      let result="";
      for(const rule of Array.from(entries || [])){
        if(++count>1000)break;
        if(rule.type===1){
          const selector=string(rule.selectorText),style=inlineStyle(rule.style);
          if(style && selector.length<=500 && !/[<@\\{}\u0000-\u001f\u007f]/.test(selector))result+=`${selector}{${style}}\n`;
        } else if(rule.type===4){
          const query=string(rule.conditionText);
          if(query.length<=400 && /^[\w\s():.,/\-]+$/.test(query))result+=`@media ${query}{${rules(rule.cssRules,depth+1)}}\n`;
        }
      }
      return result;
    }
    return rules(sheet.cssRules);
  }
  function sanitize(html,{inlineImages=[],loadRemoteImages=true,remoteData}={}) {
    // Unlike DOMParser's HTML document, detached template content cannot
    // initiate image/iframe requests while the untrusted input is parsed.
    html=string(html);
    const parsed=document.createElement("template");parsed.innerHTML=html;
    // The fragment parser omits a full document's body element. Parse just its
    // opening attributes in another inert template so body colors/classes and
    // spacing survive without keeping any original head/body node.
    let bodyAttributes="";
    const bodyTag=/<body\b((?:"[^"]*"|'[^']*'|[^'">])*)>/i.exec(html);
    if(bodyTag && bodyTag[1].length<=10000){
      const wrapper=document.createElement("template");wrapper.innerHTML=`<div${bodyTag[1]}></div>`;
      const original=wrapper.content.childNodes[0];
      if(original?.nodeType===1 && original.localName==="div"){
        const style=inlineStyle(original.style);if(style)bodyAttributes+=` style="${escape(style)}"`;
        for(const name of ["class","id"]){const value=string(original.getAttribute(name)).slice(0,500);if(value && /^[\w\s-]+$/.test(value))bodyAttributes+=` ${name}="${escape(value)}"`;}
        const color=string(original.getAttribute("bgcolor"));if(/^(?:#[0-9a-f]{3,8}|[a-z]{1,30})$/i.test(color))bodyAttributes+=` bgcolor="${color}"`;
        const dir=original.getAttribute("dir");if(["ltr","rtl","auto"].includes(dir))bodyAttributes+=` dir="${dir}"`;
      }
    }
    const images=new Map();let imageBytes=0;
    for(const image of (Array.isArray(inlineImages)?inlineImages:[]).slice(0,64)) {
      const value=raster(image?.content_type,image?.data),name=cid(image?.cid);
      if(value && name && !images.has(name) && imageBytes+value.length<=16*1024*1024){images.set(name,value);imageBytes+=value.length;}
    }
    let remoteImages=0,nodes=0,styleBytes=0;const text=[],styles=[],remoteSources=new Set();
    function walk(node,depth=0) {
      if(++nodes>30000 || depth>80)return "";
      if(node.nodeType===3){text.push(node.textContent || "");return escape(node.textContent || "");}
      if(node.nodeType!==1)return "";
      const tag=node.localName?.toLowerCase();
      if(node.namespaceURI!==htmlNamespace)return "";
      if(tag==="style"){
        const css=string(node.textContent);
        if(styleBytes+css.length<=200000){styleBytes+=css.length;styles.push(stylesheet(css));}
        return "";
      }
      if(discarded.has(tag))return "";
      if(blocks.has(tag) || tag==="br")text.push("\n");
      const contents=()=>Array.from(node.childNodes).map(child=>walk(child,depth+1)).join("");
      if(!allowed.has(tag))return contents();
      let attributes="";
      const title=string(node.getAttribute("title")).slice(0,500);
      if(title)attributes+=` title="${escape(title)}"`;
      const dir=node.getAttribute("dir");if(["ltr","rtl","auto"].includes(dir))attributes+=` dir="${dir}"`;
      for(const name of ["class","id"]){const value=string(node.getAttribute(name)).slice(0,500);if(value && /^[\w\s-]+$/.test(value))attributes+=` ${name}="${escape(value)}"`;}
      const style=inlineStyle(node.style);if(style)attributes+=` style="${escape(style)}"`;
      if(["table","td","th","col","colgroup","hr","img"].includes(tag)){
        for(const name of ["width","height"]){const value=string(node.getAttribute(name));if(/^(?:[1-9][0-9]{0,3}|10000)%?$/.test(value))attributes+=` ${name}="${value}"`;}
        const align=string(node.getAttribute("align")).toLowerCase();if(["left","center","right","justify"].includes(align))attributes+=` align="${align}"`;
        const valign=string(node.getAttribute("valign")).toLowerCase();if(["top","middle","bottom","baseline"].includes(valign))attributes+=` valign="${valign}"`;
        const color=string(node.getAttribute("bgcolor"));if(/^(?:#[0-9a-f]{3,8}|[a-z]{1,30})$/i.test(color))attributes+=` bgcolor="${color}"`;
      }
      if(tag==="table")for(const name of ["cellpadding","cellspacing","border"]){const raw=node.getAttribute(name),value=Number(raw);if(raw!==null&&Number.isInteger(value)&&value>=0&&value<=100)attributes+=` ${name}="${value}"`;}
      if(tag==="font"){
        const color=string(node.getAttribute("color")),face=string(node.getAttribute("face")),size=string(node.getAttribute("size"));
        if(/^(?:#[0-9a-f]{3,8}|[a-z]{1,30})$/i.test(color))attributes+=` color="${color}"`;
        if(/^[\w\s,'"-]{1,150}$/.test(face))attributes+=` face="${escape(face)}"`;
        if(/^[+-]?[1-7]$/.test(size))attributes+=` size="${size}"`;
      }
      if(tag==="a") {
        const href=safeUrl(node.getAttribute("href"));
        if(href)attributes+=` href="${escape(href)}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer"`;
      }
      if(tag==="td" || tag==="th")for(const name of ["colspan","rowspan"]){const value=Number(node.getAttribute(name));if(Number.isInteger(value)&&value>0&&value<=100)attributes+=` ${name}="${value}"`;}
      if(tag==="img") {
        const source=string(node.getAttribute("src")).trim(),alt=string(node.getAttribute("alt")).slice(0,500);
        let src="",label="Image unavailable";
        if(/^cid:/i.test(source)){let name=source.slice(4);try{name=decodeURIComponent(name);}catch{}src=images.get(cid(name)) || "";}
        else if(/^data:/i.test(source)){const match=/^data:(image\/[^;,]+);base64,([\s\S]*)$/i.exec(source);if(match)src=raster(match[1],match[2]);}
        else {const url=safeUrl(source,true);if(url){remoteImages++;remoteSources.add(url);label="Image unavailable";src=remoteData?.get(url) || (loadRemoteImages?url:"");}}
        if(!src){text.push(alt?`[${alt}]`:"");return `<span class="mail-image-placeholder">${escape(alt || t(label))}</span>`;}
        attributes+=` src="${escape(src)}" alt="${escape(alt)}" referrerpolicy="no-referrer" decoding="async"`;
      }
      const result=`<${tag}${attributes}>${voids.has(tag)?"":contents()+`</${tag}>`}`;
      if(blocks.has(tag))text.push("\n");return result;
    }
    const clean=Array.from(parsed.content.childNodes).map(node=>walk(node)).join("");
    return {html:clean,styles:styles.join("\n"),bodyAttributes,text:text.join("").replace(/\n[\t ]*\n(?:[\t ]*\n)+/g,"\n\n").trim(),remoteImages,remoteSources};
  }
  function sourceDocument(body,styles,bodyAttributes) {
    const origin=new URL(location.href).origin;
    const style=new URL("/mail-reader.css",origin).href;
    const policy=`default-src 'none'; script-src 'none'; style-src ${origin} 'unsafe-inline'; img-src data: https: http:; font-src 'none'; connect-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'`;
    const theme=document.documentElement.dataset.theme==="dark"?"dark":"light";
    const reading=["large","larger"].includes(document.documentElement.dataset.reading)?document.documentElement.dataset.reading:"standard";
    return `<!doctype html><html lang="${escape(PostPlusI18n.language)}" data-theme="${theme}" data-reading="${reading}"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${escape(policy)}"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="${escape(style)}"><style>${styles}</style></head><body${bodyAttributes}>${body}</body></html>`;
  }
  function node(tag,className,text) {const element=document.createElement(tag);if(className)element.className=className;if(text!==undefined)element.textContent=text;return element;}
  function create(container) {
    let current=null,disposed=false,version=0,remoteData=new Map(),proxyImages=false;
    function clear() {version++;current=null;remoteData=new Map();proxyImages=false;container.replaceChildren();}
    function render() {
      container.replaceChildren();if(!current || disposed)return;
      let count=0;const visited=new Set();
      function messageBody(message,depth=0,host=container) {
        if(!message || typeof message!=="object" || visited.has(message) || depth>8 || ++count>32)return;
        visited.add(message);
        const section=node("section",depth?"forwarded-message":"mail-reader-message");
        if(depth) {
          section.append(node("p","eyebrow",t("Forwarded message")),node("h3","forwarded-subject",string(message.subject)||t("(No subject)")));
          const headers=node("dl","message-meta forwarded-meta");
          for(const [key,label] of [["from","From"],["to","To"],["date","Date"]]){const row=node("div");row.append(node("dt","",t(label)),node("dd","",string(message[key]) || "—"));headers.append(row);}
          section.append(headers);
        }
        const body=node("div","mail-reader-body");section.append(body);
        const html=string(message.html),clean=html?sanitize(html,{inlineImages:message.inline_images,loadRemoteImages:!proxyImages,remoteData}):null;
        if(clean?.html) {
          const frame=node("iframe","mail-html-frame");frame.setAttribute("sandbox","allow-popups allow-popups-to-escape-sandbox");
          frame.setAttribute("title",t("Formatted message (scroll to read)"));frame.setAttribute("referrerpolicy","no-referrer");frame.setAttribute("credentialless","");
          frame.srcdoc=sourceDocument(clean.html,clean.styles,clean.bodyAttributes);body.append(frame);
        } else body.append(node("pre","message-body mail-plain-body",string(message.text) || clean?.text || t("(Empty message)")));
        host.append(section);
        const forwards=Array.isArray(message.forwarded)?message.forwarded:[];
        if(forwards.length){const thread=node("div","forwarded-thread");section.append(thread);for(const forwarded of forwards)messageBody(forwarded,depth+1,thread);}
      }
      messageBody(current);
    }
    const translate=()=>render();document.addEventListener("postplus:language",translate);
    const appearance=typeof MutationObserver!=="undefined"?new MutationObserver(()=>{if(current)render();}):null;
    appearance?.observe(document.documentElement,{attributes:true,attributeFilter:["data-theme","data-reading"]});
    function show(message,{loadImage}={}) {
      clear();current=message;proxyImages=typeof loadImage==="function";render();
      if(!proxyImages)return;
      const selectedVersion=version,entries=[],seen=new Set();let total=0;
      function collect(value,depth=0){
        if(!value || typeof value!=="object" || depth>8)return;
        const sources=sanitize(string(value.html),{loadRemoteImages:false}).remoteSources;
        for(const image of (Array.isArray(value.remote_images)?value.remote_images:[])){
          const url=safeUrl(image?.url,true),index=image?.index;
          if(entries.length<64 && url && sources.has(url) && Number.isInteger(index) && index>=0 && index<64 && !seen.has(url)){seen.add(url);entries.push({url,index});}
        }
        for(const forward of (Array.isArray(value.forwarded)?value.forwarded:[]).slice(0,32))collect(forward,depth+1);
      }
      collect(message);let next=0,renderQueued=false;
      function queueRender(){
        if(renderQueued)return;
        renderQueued=true;
        Promise.resolve().then(()=>{renderQueued=false;if(selectedVersion===version && !disposed)render();});
      }
      async function worker(){
        while(next<entries.length && selectedVersion===version && !disposed){
          const image=entries[next++];
          try {
            const response=await loadImage(image.index);
            if(selectedVersion!==version || disposed)return;
            const data=raster(response?.content_type,response?.data);
            if(data && total+data.length<=16*1024*1024){remoteData.set(image.url,data);total+=data.length;queueRender();}
          } catch { /* A failed remote image cannot hide an otherwise readable message. */ }
        }
      }
      for(let workerIndex=0;workerIndex<Math.min(4,entries.length);workerIndex++)worker();
    }
    return {show,clear,dispose(){clear();disposed=true;document.removeEventListener("postplus:language",translate);appearance?.disconnect();}};
  }
  return {create,sanitize,bodySource};
})();
