"use strict";
// Mail markup is reconstructed from an inert document. No sender-owned node is
// inserted into the portal, and the rendered document has an opaque origin.
window.PostPlusMailReader = (() => {
  const htmlNamespace="http://www.w3.org/1999/xhtml";
  const allowed=new Set("a b blockquote br caption code col colgroup dd del div dl dt em figcaption figure h1 h2 h3 h4 h5 h6 hr i img li ol p pre s small span strong sub sup table tbody td th thead tfoot tr u ul wbr".split(" "));
  const discarded=new Set("script style iframe frame frameset object embed applet audio video source track form input textarea select option button base meta link noscript template svg math canvas".split(" "));
  const blocks=new Set("blockquote caption dd div dl dt figcaption figure h1 h2 h3 h4 h5 h6 hr li ol p pre table tbody td th thead tfoot tr ul".split(" "));
  const voids=new Set(["br","col","hr","img","wbr"]);
  const safeStyles=new Set("color background-color font-family font-size font-weight font-style font-variant line-height letter-spacing word-spacing text-align text-decoration text-decoration-color text-decoration-line text-decoration-style text-indent text-transform white-space vertical-align border border-top border-right border-bottom border-left border-width border-style border-color border-top-width border-right-width border-bottom-width border-left-width border-top-style border-right-style border-bottom-style border-left-style border-top-color border-right-color border-bottom-color border-left-color border-radius border-collapse border-spacing margin margin-top margin-right margin-bottom margin-left padding padding-top padding-right padding-bottom padding-left width max-width height max-height box-sizing display list-style-type".split(" "));
  const t=(...args)=>PostPlusI18n.t(...args);
  const string=value=>typeof value==="string"?value:"";
  const escape=value=>string(value).replace(/[&<>"']/g,char=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
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
      if(property==="display" && !["block","inline","inline-block","table","table-row","table-cell","table-row-group","table-header-group","table-footer-group","list-item","none"].includes(value))continue;
      result.push(`${property}:${value}`);
    }
    return result.join(";");
  }
  function sanitize(html,{inlineImages=[],loadRemoteImages=false}={}) {
    // Unlike DOMParser's HTML document, detached template content cannot
    // initiate image/iframe requests while the untrusted input is parsed.
    const parsed=document.createElement("template");parsed.innerHTML=string(html);
    const images=new Map();let imageBytes=0;
    for(const image of (Array.isArray(inlineImages)?inlineImages:[]).slice(0,64)) {
      const value=raster(image?.content_type,image?.data),name=cid(image?.cid);
      if(value && name && !images.has(name) && imageBytes+value.length<=16*1024*1024){images.set(name,value);imageBytes+=value.length;}
    }
    let remoteImages=0,nodes=0;const text=[];
    function walk(node,depth=0) {
      if(++nodes>30000 || depth>80)return "";
      if(node.nodeType===3){text.push(node.textContent || "");return escape(node.textContent || "");}
      if(node.nodeType!==1)return "";
      const tag=node.localName?.toLowerCase();
      if(node.namespaceURI!==htmlNamespace || discarded.has(tag))return "";
      if(blocks.has(tag) || tag==="br")text.push("\n");
      const contents=()=>Array.from(node.childNodes).map(child=>walk(child,depth+1)).join("");
      if(!allowed.has(tag))return contents();
      let attributes="";
      const title=string(node.getAttribute("title")).slice(0,500);
      if(title)attributes+=` title="${escape(title)}"`;
      const dir=node.getAttribute("dir");if(["ltr","rtl","auto"].includes(dir))attributes+=` dir="${dir}"`;
      const style=inlineStyle(node.style);if(style)attributes+=` style="${escape(style)}"`;
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
        else {const url=safeUrl(source,true);if(url){remoteImages++;label="Remote image blocked";if(loadRemoteImages)src=url;}}
        if(!src){text.push(alt?`[${alt}]`:"");return `<span class="mail-image-placeholder">${escape(alt || t(label))}</span>`;}
        attributes+=` src="${escape(src)}" alt="${escape(alt)}" referrerpolicy="no-referrer" decoding="async"`;
        for(const name of ["width","height"]){const value=Number(node.getAttribute(name));if(Number.isInteger(value)&&value>0&&value<=4096)attributes+=` ${name}="${value}"`;}
      }
      const result=`<${tag}${attributes}>${voids.has(tag)?"":contents()+`</${tag}>`}`;
      if(blocks.has(tag))text.push("\n");return result;
    }
    const clean=Array.from(parsed.content.childNodes).map(node=>walk(node)).join("");
    return {html:clean,text:text.join("").replace(/\n[\t ]*\n(?:[\t ]*\n)+/g,"\n\n").trim(),remoteImages};
  }
  function sourceDocument(body,loadRemoteImages) {
    const origin=new URL(location.href).origin;
    const style=new URL("/mail-reader.css",origin).href;
    const policy=`default-src 'none'; script-src 'none'; style-src ${origin} 'unsafe-inline'; img-src data:${loadRemoteImages?" https: http:":""}; font-src 'none'; connect-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'`;
    const theme=document.documentElement.dataset.theme==="dark"?"dark":"light";
    const reading=["large","larger"].includes(document.documentElement.dataset.reading)?document.documentElement.dataset.reading:"standard";
    return `<!doctype html><html lang="${escape(PostPlusI18n.language)}" data-theme="${theme}" data-reading="${reading}"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${escape(policy)}"><meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="${escape(style)}"></head><body>${body}</body></html>`;
  }
  function node(tag,className,text) {const element=document.createElement(tag);if(className)element.className=className;if(text!==undefined)element.textContent=text;return element;}
  function create(container) {
    let current=null,plain=false,remote=false,disposed=false;
    function clear() {current=null;plain=false;remote=false;container.replaceChildren();}
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
        const html=string(message.html),clean=html?sanitize(html,{inlineImages:message.inline_images,loadRemoteImages:remote}):null;
        if(clean?.html && !plain) {
          const frame=node("iframe","mail-html-frame");frame.setAttribute("sandbox","allow-popups allow-popups-to-escape-sandbox");
          frame.setAttribute("title",t("Formatted message (scroll to read)"));frame.setAttribute("referrerpolicy","no-referrer");frame.setAttribute("credentialless","");
          frame.srcdoc=sourceDocument(clean.html,remote);body.append(frame);
        } else body.append(node("pre","message-body mail-plain-body",string(message.text) || clean?.text || t("(Empty message)")));
        if(clean?.html) {
          const tools=node("div","mail-reader-tools"),toggle=node("button","button secondary",t(plain?"Show formatted message":"Show plain text"));
          toggle.type="button";toggle.addEventListener("click",()=>{plain=!plain;render();});tools.append(toggle);
          if(!plain && clean.remoteImages && !remote) {
            const images=node("button","button secondary",t("Load remote images"));images.type="button";images.addEventListener("click",()=>{remote=true;render();});tools.append(images);
            tools.append(node("p","field-hint",t("Remote images are blocked. Loading them contacts external servers and may reveal that you opened this message.")));
          }
          // Keep controls before the document so they are reachable without
          // scrolling an isolated document to its end.
          body.prepend(tools);
        }
        host.append(section);
        const forwards=Array.isArray(message.forwarded)?message.forwarded:[];
        if(forwards.length){const thread=node("div","forwarded-thread");section.append(thread);for(const forwarded of forwards)messageBody(forwarded,depth+1,thread);}
      }
      messageBody(current);
    }
    const translate=()=>render();document.addEventListener("postplus:language",translate);
    const appearance=typeof MutationObserver!=="undefined"?new MutationObserver(()=>{if(current)render();}):null;
    appearance?.observe(document.documentElement,{attributes:true,attributeFilter:["data-theme","data-reading"]});
    return {show(message){clear();current=message;render();},clear,dispose(){clear();disposed=true;document.removeEventListener("postplus:language",translate);appearance?.disconnect();}};
  }
  return {create,sanitize};
})();
