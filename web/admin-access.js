"use strict";
window.PostPlusAdminAccess={mount(root,{api,notice,inviteActions,afterDelete}){
  const t=(...args)=>PostPlusI18n.t(...args);
  let version=0,inviteVersion=0,ruleVersion=0,dialogVersion=0,active=true,deleting=false;
  const panels=[];
  const node=(tag,text,className)=>{const e=document.createElement(tag);if(text)e.textContent=t(text);if(className)e.className=className;return e;};
  function input(form,label,type="text",value=""){
    const e=node("input"),l=node("label",label);e.type=type;e.value=value;e.setAttribute("aria-label",t(label));l.append(e);form.append(l);return e;
  }
  function table(parent,labels){
    const scroll=node("div",null,"table-scroll"),table=node("table"),head=node("thead"),row=node("tr"),body=node("tbody");
    scroll.tabIndex=0;scroll.setAttribute("role","region");scroll.setAttribute("aria-label",t(labels[0]));
    for(const label of labels){const th=node("th",label);th.scope="col";row.append(th);}head.append(row);table.append(head,body);scroll.append(table);parent.append(scroll);return body;
  }
  function section(title,hint,collapsible=false){
    const panel=node(collapsible?"details":"section",null,collapsible?"settings-group access-section":"access-section"),heading=node(collapsible?"summary":"h2",title),help=node("p",hint,"field-hint"),error=node("p",null,"form-error"),form=node("form",null,"access-form"),list=node("div");
    error.hidden=true;error.setAttribute("role","alert");panel.append(heading,help,error,form,list);panels.push(panel);return {panel,error,list,form};
  }
  function failure(panel,error){if(!active)return;panel.error.textContent=error.message;panel.error.hidden=false;}
  const invite=section("Mailbox invitations","Invite someone to create a mailbox. Links expire and can be revoked; only ordinary accounts can register.");
  const inviteDialog=node("dialog",null,"invitation-dialog"),inviteHeader=node("header",null,"dialog-header"),inviteTitle=node("h2","Mailbox invitations"),inviteClose=node("button","Close","button secondary"),inviteBody=node("div",null,"dialog-body");
  inviteClose.type="button";inviteHeader.append(inviteTitle,inviteClose);invite.panel.children[0].remove();inviteBody.append(invite.panel);inviteDialog.append(inviteHeader,inviteBody);root.append(inviteDialog);panels.push(inviteDialog);
  const inviteOpen=node("button","Invite to mailbox","button secondary");inviteOpen.type="button";(inviteActions||root).append(inviteOpen);panels.push(inviteOpen);
  inviteOpen.addEventListener("click",()=>{inviteDialog.showModal();invitations().catch(error=>failure(invite,error));});
  inviteClose.addEventListener("click",()=>inviteDialog.close());
  const name=input(invite.form,"Invitation name"),localpart=input(invite.form,"Mailbox name (optional)"),days=input(invite.form,"Expires after (days)","number","7"),uses=input(invite.form,"Maximum registrations","number","1");
  name.required=true;name.maxLength=80;localpart.maxLength=64;days.min=uses.min="1";days.max="365";uses.max="100";days.step=uses.step="1";
  const create=node("button","Create invitation","button primary");create.type="submit";invite.form.append(create);
  const output=node("div",null,"invitation-output"),link=node("textarea"),copy=node("button","Copy invitation link","button secondary"),done=node("button","Done","button secondary"),once=node("p","The invitation link is shown once. Copy it before leaving this page.","field-hint");
  output.hidden=true;link.readOnly=true;link.rows=3;link.setAttribute("aria-label",t("Invitation link"));copy.type=done.type="button";output.append(once,link,copy,done);invite.form.parentNode.append(output);
  const clear=()=>{link.value="";output.hidden=true;};done.addEventListener("click",clear);inviteDialog.addEventListener("close",()=>{dialogVersion++;clear();});
  copy.addEventListener("click",async()=>{link.focus();link.select();try{await navigator.clipboard.writeText(link.value);if(active)notice(t("Invitation link copied."));}catch{if(active)notice(t("Copy is unavailable. The link is selected; copy it manually."),true);}});
  async function invitations(){
    if(!active)return;const generation=version,load=++inviteVersion,data=await api("/api/admin/invitations");
    if(!active||generation!==version||load!==inviteVersion)return;
    invite.list.replaceChildren();
    if(!data.invitations.length){invite.list.append(node("p","No invitations yet.","muted"));return;}
    const body=table(invite.list,["Invitation name","Mailbox","Registrations","Expires","Status","Actions"]);
    for(const item of data.invitations){const row=node("tr"),identity=node("td"),mailbox=node("td"),registrations=node("td"),expires=node("td"),status=node("td"),actions=node("td"),revoke=node("button","Revoke","table-action");
      identity.textContent=item.name;mailbox.textContent=`${item.localpart||"*"}@${item.domain}`;registrations.textContent=`${item.uses}/${item.max_uses}`;expires.textContent=new Date(item.expires_at*1000).toLocaleString(PostPlusI18n.language);status.textContent=t(item.active?"Active":"Inactive");revoke.type="button";revoke.disabled=!item.active;
      revoke.addEventListener("click",async()=>{revoke.disabled=true;try{await api("/api/admin/invitations/"+item.id,{method:"DELETE"});await invitations();}catch(error){if(active){revoke.disabled=false;failure(invite,error);}}});
      actions.append(revoke);row.append(identity,mailbox,registrations,expires,status,actions);body.append(row);
    }
  }
  invite.form.addEventListener("submit",async event=>{event.preventDefault();if(create.disabled)return;invite.error.hidden=true;clear();create.disabled=true;const generation=version,dialog=dialogVersion;
    try{const body={name:name.value.trim(),localpart:localpart.value.trim(),expires_in_days:Number(days.value),max_uses:Number(uses.value)},result=await api("/api/admin/invitations",{method:"POST",body});
      if(!active||generation!==version||dialog!==dialogVersion){result.registration_url="";return;}link.value=result.registration_url;result.registration_url="";output.hidden=false;await invitations();
    }catch(error){failure(invite,error);}finally{create.disabled=false;}
  });
  const forwarding=section("Wildcard forwarding","Route matching mailbox names to a local inbox. Use * for any text and ? for one character. Existing mailboxes take priority.",true);root.append(forwarding.panel);
  const pattern=input(forwarding.form,"Mailbox pattern"),destination=input(forwarding.form,"Destination mailbox");pattern.required=destination.required=true;pattern.placeholder="sales-*";destination.placeholder="owner@example.com";destination.type="email";
  const add=node("button","Add forwarding rule","button primary");add.type="submit";forwarding.form.append(add);
  async function rules(){
    if(!active)return;const generation=version,load=++ruleVersion,data=await api("/api/admin/forwarding");if(!active||generation!==version||load!==ruleVersion)return;
    forwarding.list.replaceChildren();if(!data.rules.length){forwarding.list.append(node("p","No forwarding rules yet.","muted"));return;}
    const body=table(forwarding.list,["Mailbox pattern","Destination mailbox","Actions"]);
    for(const item of data.rules){const row=node("tr"),patternCell=node("td"),target=node("td"),actions=node("td"),remove=node("button","Remove","table-action");patternCell.textContent=`${item.pattern}@${item.domain}`;target.textContent=item.destination;remove.type="button";
      remove.addEventListener("click",async()=>{remove.disabled=true;try{await api("/api/admin/forwarding/"+item.id,{method:"DELETE"});await rules();}catch(error){if(active){remove.disabled=false;failure(forwarding,error);}}});actions.append(remove);row.append(patternCell,target,actions);body.append(row);
    }
  }
  forwarding.form.addEventListener("submit",async event=>{event.preventDefault();if(add.disabled)return;add.disabled=true;forwarding.error.hidden=true;try{await api("/api/admin/forwarding",{method:"POST",body:{pattern:pattern.value.trim(),destination:destination.value.trim()}});if(active){pattern.value="";await rules();}}catch(error){failure(forwarding,error);}finally{add.disabled=false;}});
  let deletion=null;
  function deleteAccount(account){
    if(!active||deleting)return;
    deletion?.close();deletion?.remove();
    const dialog=node("dialog"),form=node("form"),header=node("header",null,"dialog-header"),body=node("div",null,"dialog-body"),footer=node("footer",null,"dialog-footer"),title=node("h2",account.deletion_pending?"Finish deleting account":"Delete account?"),warning=node("p","This permanently removes the mailbox, stored mail, API keys, invitations and forwarding rules to this inbox. Pending mail to or from this account is removed."),identity=node("p",null,"account-delete-name"),error=node("p",null,"form-error"),confirmation=input(body,"Type the complete email address to confirm"),cancel=node("button","Cancel","button secondary"),remove=node("button",account.deletion_pending?"Finish deletion":"Delete account","button danger");
    identity.textContent=account.username;confirmation.type="email";confirmation.required=true;confirmation.autocomplete="off";confirmation.spellcheck=false;remove.type="submit";remove.disabled=true;cancel.type="button";error.hidden=true;error.setAttribute("role","alert");header.append(title);body.children[0].remove();body.append(warning,identity);const label=node("label","Type the complete email address to confirm");label.append(confirmation);body.append(label,error);footer.append(cancel,remove);form.append(header,body,footer);dialog.append(form);root.append(dialog);panels.push(dialog);deletion=dialog;
    confirmation.addEventListener("input",()=>{remove.disabled=confirmation.value.trim().toLowerCase()!==account.username.toLowerCase()||deleting;});
    cancel.addEventListener("click",()=>{if(!deleting)dialog.close();});
    dialog.addEventListener("cancel",event=>{if(deleting)event.preventDefault();});
    dialog.addEventListener("close",()=>{confirmation.value="";dialog.remove();if(deletion===dialog)deletion=null;});
    form.addEventListener("submit",async event=>{event.preventDefault();if(deleting||confirmation.value.trim().toLowerCase()!==account.username.toLowerCase())return;deleting=true;remove.disabled=cancel.disabled=true;error.hidden=true;const generation=version;
      try{await api("/api/admin/users",{method:"DELETE",body:{username:account.username,confirm_username:confirmation.value.trim()}});if(!active||generation!==version)return;dialog.close();notice(t("User account deleted."));await afterDelete?.();await rules();}
      catch(failure){if(active&&generation===version){error.textContent=failure.message;error.hidden=false;await afterDelete?.();}}
      finally{deleting=false;remove.disabled=cancel.disabled=false;}
    });dialog.showModal();confirmation.focus();
  }
  function refresh(){return Promise.allSettled([invitations().catch(error=>failure(invite,error)),rules().catch(error=>failure(forwarding,error))]);}
  refresh();return {refresh,deleteAccount,dispose(){active=false;version++;dialogVersion++;clear();panels.forEach(panel=>panel.remove());}};
}};
