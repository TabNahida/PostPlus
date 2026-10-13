"use strict";
// Run python tests/mail_reader_browser.py. All content is synthetic test data.
(async()=>{
  const result=document.getElementById("result"),container=document.getElementById("test-reader");
  const check=(condition,message)=>{if(!condition)throw new Error(message);};
  const png="iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jw1sAAAAASUVORK5CYII=";
  const probe=location.origin+"/probe.png",api=PostPlusMailReader;
  const markup=`<div style="padding:20px;background-color:#f2f4f8;border:1px solid #c8d1d9;position:fixed;inset:0;background-image:url('${probe}?css')"><h2 style="font-size:24px;color:#254e45;margin:0 0 15px">Your verification code</h2><p>Use this code to complete your sign-in:</p><p style="font-size:32px;font-weight:bold;letter-spacing:8px;text-align:center;color:#236843">123456</p><p>验证码有效期为 10 分钟。</p><table style="width:900px;border-collapse:collapse"><tr><th>Request</th><th>Status</th></tr><tr><td>Desktop and narrow screen</td><td>Ready</td></tr></table><img src="cid:logo" alt="Inline logo" width="40"><img src="${probe}?image" alt="Remote company logo"><img src="https://www.w3.org/Icons/w3c_home.png" alt="HTTPS sample logo" width="72"><a href="https://example.com/help?reader=fixture" onclick="parent.mailExploit=true" ping="${probe}?ping" target="_self">Open help in a new window</a><a href="javascript:parent.mailExploit=true">Blocked active link</a><script>parent.mailExploit=true<\/script><iframe src="${probe}?frame"></iframe><object data="${probe}?object"></object><form action="${probe}?form"><input name="password"></form><style>@import '${probe}?import';</style><svg><image href="${probe}?svg"></image></svg><link rel="preload" href="${probe}?preload" as="image"></div>`;
  const message={subject:"Fixture",from:"sender@example.com",to:"reader@example.com",date:"2026-10-13",text:"",html:markup,inline_images:[{cid:"logo",content_type:"image/png",data:png},{cid:"svg",content_type:"image/svg+xml",data:"PHN2Zy8+"}],forwarded:[{subject:"Original booking confirmation",from:"Bookings <bookings@example.com>",to:"sender@example.com",date:"2026-10-12",text:"Your booking is confirmed.\nReference: PP-2026",html:"<p style='color:#315b49;font-weight:bold'>Your booking is confirmed.</p><p>Reference: <strong>PP-2026</strong></p>",forwarded:[{subject:"Earlier question",from:"reader@example.com",to:"bookings@example.com",date:"2026-10-11",text:"Can you confirm my booking?",html:""}]}]};
  try {
    const initialProbes=await (await fetch("/probe-count",{cache:"no-store"})).json();
    const clean=api.sanitize(markup,{inlineImages:message.inline_images});
    const parsed=document.createElement("template");parsed.innerHTML=clean.html;
    check(!parsed.content.querySelector("script,iframe,object,form,input,svg,style,link"),"Active elements survived sanitation");
    check(!parsed.content.querySelector("[onclick],[ping],[srcset],[id]"),"Active or portal-owned attributes survived");
    check(parsed.content.querySelector("h2").style.fontSize==="24px","Safe inline typography was lost");
    check(parsed.content.querySelector("div").style.padding==="20px","Safe spacing was lost");
    check(!parsed.content.querySelector("div").style.position && !parsed.content.querySelector("div").style.backgroundImage,"Active layout or CSS resource survived");
    const link=parsed.content.querySelector("a[href]");check(link.target==="_blank"&&link.rel==="noopener noreferrer","Link isolation failed");
    check(clean.remoteImages===2&&!clean.html.includes('src="'+probe),"Remote tracking image was not blocked");
    check(parsed.content.querySelector("img").src.startsWith("data:image/png;base64,"),"CID raster image was not resolved");
    for(const html of ["<img src=javascript:alert(1) onerror=alert(1)>","<svg><foreignObject><img src='"+probe+"?namespace'></foreignObject></svg>","<math><mtext><table><mglyph><style><!--</style><img title='--><img src="+probe+"?mutation onerror=alert(1)>'>","<noscript><p title='</noscript><img src="+probe+"?noscript onerror=alert(1)>'>"]) {
      const safe=api.sanitize(html);const tree=document.createElement("template");tree.innerHTML=safe.html;
      check(!tree.content.querySelector("[onerror],script,svg,math,iframe,style"),"Malformed markup sanitizer regression");
      check(!tree.content.querySelector("img[src]"),"Malformed markup loaded a resource");
    }
    check(api.sanitize(`<img src="https://example.com/image.png">`,{loadRemoteImages:true}).html.includes('src="https://example.com/image.png"'),"Explicit HTTPS images were not accepted");
    check(api.sanitize(`<img src="http://example.com/image.png">`,{loadRemoteImages:true}).html.includes('src="http://example.com/image.png"'),"Explicit HTTP images were not accepted");
    const reader=api.create(container);reader.show(message);
    check(container.querySelectorAll("iframe").length===2,"Formatted forwarded body missing");
    for(const frame of container.querySelectorAll("iframe"))check(!frame.sandbox.contains("allow-scripts")&&!frame.sandbox.contains("allow-same-origin"),"Mail iframe must retain an opaque sandbox");
    document.getElementById("clear").addEventListener("click",()=>{reader.clear();result.textContent="Message cleared. No mail document remains.";});
    document.getElementById("replace").addEventListener("click",()=>{reader.show(message);result.textContent="Another message opened. Remote images are blocked again.";});
    document.getElementById("language").addEventListener("click",()=>PostPlusI18n.setLanguage("zh-CN",false));
    await new Promise(resolve=>setTimeout(resolve,300));
    const probes=await (await fetch("/probe-count",{cache:"no-store"})).json();
    check(probes.count===initialProbes.count,"Default rendering or inert parsing contacted a tracker");
    check(!window.mailExploit,"Mail script executed in portal");
    result.textContent="Security checks passed. Default parsing and rendering made zero tracking requests; formatted HTML, safe inline CSS, CID images and nested forwards are ready.";
    document.documentElement.dataset.testResult="passed";
  } catch(error){result.textContent="FAIL: "+error.message;document.documentElement.dataset.testResult="failed";}
})();
