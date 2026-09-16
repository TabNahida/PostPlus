"use strict";
window.PostPlusAcme = (() => {
  const t=(...args)=>PostPlusI18n.t(...args);
  function node(tag,text,className) {const item=document.createElement(tag);if(text){item.dataset.i18n=text;item.textContent=t(text);}if(className)item.className=className;return item;}
  function create(root,{request,domain="",onCertificate,prefix="acme"}) {
    const panel=node("details",null,"acme-panel");panel.append(node("summary","Get a certificate from Let's Encrypt"));
    panel.append(node("p","Point your domain's DNS to this server and forward public TCP port 80 to PostPlus for HTTP-01 validation.","field-hint"));
    panel.append(node("p","Start with staging to check your setup. Staging certificates are for testing and are not trusted by browsers or mail clients.","field-hint"));
    const form=node("div",null,"acme-fields"),grid=node("div",null,"grid-two");
    function field(label,name,type,value) {const wrap=node("div"),text=node("label",label),input=node("input");text.htmlFor=`${prefix}-${name}`;input.id=text.htmlFor;input.type=type;input.value=value;input.autocomplete="off";wrap.append(text,input);grid.append(wrap);return input;}
    const host=field("Certificate domain","domain","text",domain),email=field("Certificate contact email","email","email","");
    form.append(grid);const directoryLabel=node("label","Certificate environment"),directory=node("select");directory.id=`${prefix}-directory`;directoryLabel.htmlFor=directory.id;
    for(const [value,label] of [["staging","Staging · test certificate"],["production","Production · trusted certificate"]]){const option=node("option",label);option.value=value;directory.append(option);}
    directory.value="staging";
    form.append(directoryLabel,directory);
    const termsButton=node("button","Load certificate authority terms","button secondary");termsButton.type="button";
    const termsLink=node("a","Read the certificate authority terms ↗");termsLink.target="_blank";termsLink.rel="noopener noreferrer";termsLink.hidden=true;
    const consentLabel=node("label",null,"checkbox-label"),consent=node("input");consent.type="checkbox";consent.disabled=true;consentLabel.append(consent,node("span","I have read and agree to the certificate authority terms."));
    const actions=node("div",null,"acme-actions"),start=node("button","Request certificate","button primary"),cancel=node("button","Cancel request","button secondary");start.type="button";cancel.type="button";cancel.hidden=true;
    actions.append(start,cancel);const status=node("p",null,"field-hint"),error=node("p",null,"form-error");status.setAttribute("role","status");error.setAttribute("role","alert");error.hidden=true;
    const result=node("div",null,"acme-result");result.hidden=true;const certificate=node("input"),key=node("input");certificate.readOnly=true;key.readOnly=true;
    const certificateLabel=node("label","Issued certificate file"),keyLabel=node("label","Issued private key file");certificate.id=`${prefix}-issued-certificate`;key.id=`${prefix}-issued-key`;certificateLabel.htmlFor=certificate.id;keyLabel.htmlFor=key.id;
    const expiry=node("p",null,"field-hint"),apply=node("button","Use these certificate paths","button secondary");apply.type="button";result.append(certificateLabel,certificate,keyLabel,key,expiry,apply);
    form.append(termsButton,termsLink,consentLabel,actions,status,error,result);panel.append(form);root.replaceChildren(panel);
    let terms="",job=null,timer=null,running=false,lastStatus="",disposed=false,loadingTerms=false,cancelling=false,version=0;
    function fail(problem) {error.hidden=false;error.textContent=problem.message || PostPlusI18n.error(problem);}
    function render() {status.textContent=lastStatus ? t(lastStatus) : "";start.disabled=running || loadingTerms || !terms || !consent.checked;cancel.hidden=!running;cancel.disabled=cancelling;host.disabled=running;email.disabled=running;directory.disabled=running || loadingTerms;termsButton.disabled=running || loadingTerms;consent.disabled=running || loadingTerms || !terms;expiry.hidden=!job?.result?.expires_at;expiry.textContent=job?.result?.expires_at ? t("Certificate expires: {date}",{date:job.result.expires_at}) : "";}
    function resetTerms() {terms="";consent.checked=false;consent.disabled=true;termsLink.hidden=true;render();}
    directory.addEventListener("change",resetTerms);consent.addEventListener("change",render);
    termsButton.addEventListener("click",async()=>{
      if(running || loadingTerms || disposed)return;
      error.hidden=true;loadingTerms=true;resetTerms();
      try {const data=await request(`/terms?directory=${encodeURIComponent(directory.value)}`);if(disposed)return;const url=new URL(data.terms_of_service);if(url.protocol!=="https:" || url.username || url.password)throw new Error(t("The certificate authority returned an invalid terms link."));terms=data.terms_of_service;termsLink.href=terms;termsLink.hidden=false;}
      catch(problem){if(!disposed)fail(problem);}finally{loadingTerms=false;if(!disposed)render();}
    });
    async function showJob(data) {
      if(disposed)return;
      job=data;const state=data.state || "idle";
      const terminal=["succeeded","issued","completed","valid","failed","cancelled","canceled","idle"].includes(state);
      running=!terminal;
      lastStatus=({idle:"No certificate request is running.",queued:"Certificate request queued.",connecting:"Reading the certificate authority directory.",ordering:"Creating an order for the requested domain.",authorizing:"Waiting for domain validation over public HTTP port 80.",finalizing:"Submitting a signed certificate request.",downloading:"Downloading and validating the issued certificate chain.",succeeded:"Certificate issued.",issued:"Certificate issued.",completed:"Certificate issued.",valid:"Certificate issued.",failed:"Certificate request failed.",cancelled:"Certificate request cancelled.",canceled:"Certificate request cancelled."})[state] || "Certificate request is running. DNS validation can take a few minutes.";
      const issued=data.result || data;
      certificate.value=issued.tls_certificate || "";
      key.value=issued.tls_private_key || "";
      result.hidden=!(certificate.value && key.value);apply.hidden=issued.staging===true || data.directory==="staging";
      error.hidden=!data.error;
      if(data.error)fail({message:PostPlusI18n.error({error:data.error,code:data.code})});
      render();clearTimeout(timer);
      if(running)timer=setTimeout(poll,2500);
    }
    async function poll() {
      const current=version;
      try {const data=await request(`/status${job?.job_id ? `?job_id=${encodeURIComponent(job.job_id)}` : ""}`);if(!disposed && current===version)await showJob(data);}
      catch(problem){if(disposed || current!==version)return;fail(problem);if(running){lastStatus="Could not refresh certificate status. Retrying…";clearTimeout(timer);timer=setTimeout(poll,2500);}render();}
    }
    start.addEventListener("click",async()=>{
      if(running || loadingTerms || disposed)return;
      error.hidden=true;if(!host.value.trim() || !email.value.trim() || !email.checkValidity()){fail({message:t("Enter a certificate domain and a valid contact email.")});return;}
      if(!consent.checked || !terms)return;
      version++;clearTimeout(timer);running=true;result.hidden=true;lastStatus="Starting certificate request…";render();
      try {await showJob(await request("/start",{method:"POST",body:{domain:host.value.trim(),email:email.value.trim(),directory:directory.value,agree_terms:true,terms_of_service:terms}}));}
      catch(problem){running=false;render();fail(problem);}
    });
    cancel.addEventListener("click",async()=>{
      if(!job?.job_id || cancelling || !running || disposed)return;
      version++;clearTimeout(timer);cancelling=true;render();
      try {const data=await request("/cancel",{method:"POST",body:{job_id:job.job_id}});if(disposed)return;if(data.state)await showJob(data);else{lastStatus="Cancellation requested. Waiting for the request to stop…";render();timer=setTimeout(poll,2500);}}
      catch(problem){if(!disposed){fail(problem);timer=setTimeout(poll,2500);}}
      finally{cancelling=false;if(!disposed)render();}
    });
    apply.addEventListener("click",async()=>{if(disposed || apply.hidden || apply.disabled)return;apply.disabled=true;try{await onCertificate({tls_certificate:certificate.value,tls_private_key:key.value});if(disposed)return;lastStatus="Certificate paths filled. Review and save your configuration.";render();}catch(problem){if(!disposed)fail(problem);}finally{apply.disabled=false;}});
    panel.addEventListener("toggle",()=>{if(panel.open && !running)poll();});
    render();
    return {translate(){PostPlusI18n.apply(root);render();},setDomain(value){if(!host.value)host.value=value;},dispose(){disposed=true;version++;clearTimeout(timer);}};
  }
  return {create};
})();
