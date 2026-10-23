"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const {fixture}=require("./api_keys_ui_test.js");
const urls={admin_url:"http://localhost:8081/",web_url:"http://localhost:8080/"};
const job=(services=["smtp","delivery"],state="pending")=>({ok:true,job_id:"restart-test",state,services,...urls});
async function ready() {
  const f=fixture();await f.ready();f.sandbox.saved={revision:"revision-1",restart_available:true,...urls};
  f.run('settingsData=saved;settingsEditor={read:()=>({log_level:"warn"}),clearSecrets(){},dispose(){},highlight(){}};renderServiceRestarts();');
  return f;
}
async function run() {
  const html=fs.readFileSync(path.join(__dirname,"../web/admin.html"),"utf8");
  for(const id of ["restart-open","restart-panel","restart-status","restart-dialog","restart-service-groups","restart-unavailable","restart-dialog-title","restart-dialog-submit"])assert.match(html,new RegExp(`id="${id}"`));
  const sections=[];let restartParent;
  for(const match of html.matchAll(/<section\b[^>]*>|<\/section>/g)) {
    if(match[0]==="</section>")sections.pop();
    else {
      const id=match[0].match(/\bid="([^"]+)"/)?.[1];
      if(id==="restart-panel")restartParent=sections.at(-1);
      sections.push(id);
    }
  }
  assert.equal(restartParent,"view-restart","Restart progress belongs only to the restart page");
  const navigation=await ready();
  for(const view of ["maintenance","restart","settings"]){
    assert.match(html,new RegExp(`id="nav-${view}"`));assert.match(html,new RegExp(`id="view-${view}"`));
    await navigation.run(`switchView("${view}")`);
    assert.equal(navigation.id(`view-${view}`).hidden,false);assert.equal(navigation.id("admin-refresh").hidden,true);
    for(const other of ["maintenance","restart","settings"].filter(name=>name!==view))assert.equal(navigation.id(`view-${other}`).hidden,true);
  }
  assert.equal(navigation.calls.length,0,"Operation pages reuse loaded settings without discarding unsaved edits");
  navigation.run("updateSettingsCount(3)");assert.equal(navigation.id("settings-change-count").textContent,"3 settings changed");
  navigation.run("updateSettingsCount(0)");assert.equal(navigation.id("settings-change-count").textContent,"No unsaved changes");
  const f=await ready();let status=job();
  f.respond((route,options)=>route==="/api/admin/config"?{ok:true,restart_required:false,restart:job(),...urls}:status);
  assert.equal(await f.run("saveSettings()"),true);
  assert.deepEqual(JSON.parse(f.calls[0].options.body),{revision:"revision-1",values:{log_level:"warn"}});
  assert.equal(f.id("settings-form").hidden,true);assert.equal(f.id("restart-panel").hidden,false);
  assert.equal(f.run("state.view"),"restart","A new restart opens its single progress location");
  assert.equal(f.id("view-restart").hidden,false);assert.equal(f.id("view-settings").hidden,true);
  assert.equal(f.id("backup-create").disabled,true);assert.equal(f.run("restartBusy"),true);
  assert.match(f.id("restart-status").textContent,/Restarting affected/);
  await f.tick();assert.equal(f.run("restartBusy"),true,"Pending status does not report completion");
  status=job(["smtp","delivery"],"complete");await f.tick();
  assert.equal(f.run("restartBusy"),false);assert.match(f.id("restart-status").textContent,/session remains available/);
  assert.equal(f.run("state.user.username"),"admin@example.com");
  await f.run('switchView("settings")');
  assert.equal(f.id("view-restart").hidden,true,"Completed restart progress is hidden when leaving its page");
  const standalone=await ready();standalone.respond(()=>({ok:true,restart_required:true,...urls}));
  assert.equal(await standalone.run("saveSettings()"),true);assert.equal(standalone.timers.size,0);
  assert.match(standalone.id("settings-success-message").textContent,/standalone service cannot restart/);
  const domains=await ready();domains.respond(route=>route==="/api/admin/config"?{ok:true,restart_available:true,restart:job(["smtp"],"complete"),...urls}:job(["auth","smtp","web","admin"]));
  await domains.run('applyDomainChanges({restart_required:true})');
  assert.equal(domains.calls[0].route,"/api/admin/config");assert.equal(domains.calls[1].route,"/api/admin/restart");assert.deepEqual(JSON.parse(domains.calls[1].options.body),{mode:"changed"});assert.equal(domains.run("state.view"),"restart");assert.equal(domains.run("restartBusy"),true,"Domain activation schedules and tracks the affected services");
  const standaloneDomains=await ready();standaloneDomains.respond(()=>({ok:true,restart_available:false,...urls}));await standaloneDomains.run('applyDomainChanges({restart_required:true})');assert.equal(standaloneDomains.calls.length,1);assert.match(standaloneDomains.id("notice").textContent,/Restart PostPlus manually/);
  const failedDomains=await ready();failedDomains.respond(()=>({ok:true,restart_available:true,...urls}));failedDomains.sandbox.fetch=async route=>route==="/api/admin/config"?{ok:true,json:async()=>({ok:true,restart_available:true,...urls})}:{ok:false,status:409,json:async()=>({ok:false,error:"Wait"})};await failedDomains.run('applyDomainChanges({restart_required:true})');assert.match(failedDomains.id("notice").textContent,/saved, but restarting failed/);
  const shutdown=await ready();shutdown.respond(()=>({ok:true,restart_required:true,...urls}));
  assert.equal(await shutdown.run("saveSettings({apply:false})"),true);
  assert.equal(JSON.parse(shutdown.calls[0].options.body).apply,false);assert.equal(shutdown.timers.size,0);
  assert.match(shutdown.id("settings-success-message").textContent,/without restarting/);
  const serviceNames=["auth","storage","filter","transfer","delivery","smtp","pop3","imap","web","admin"];
  const catalog=await ready();assert.deepEqual([...catalog.run("restartServiceButtons.keys()")].sort(),serviceNames.toSorted());
  assert.equal(catalog.id("restart-service-groups").children[0].children.length,3,"Modules are grouped into protocol, portal and internal services");
  for(const service of serviceNames){
    const individual=await ready();individual.respond(()=>({...job([service]),mode:"service",service}));
    assert.equal(individual.run(`restartServiceButtons.get("${service}").disabled`),false);
    await individual.run(`restartServiceButtons.get("${service}").fire("click")`);
    assert.equal(individual.id("restart-dialog").open,true);
    assert.match(individual.id("restart-dialog-title").textContent,/^Restart .+\?$/);
    assert.match(individual.id("restart-dialog-summary").textContent,/Only .+ will restart/);
    if(service==="admin")assert.match(individual.id("restart-dialog-impact").textContent,/Administration will disconnect/);
    if(service==="web")assert.match(individual.id("restart-dialog-impact").textContent,/Webmail users must sign in again/);
    await individual.id("restart-form").fire("submit");
    assert.equal(individual.calls.length,1,"Individual restart does not save unrelated form edits");
    assert.equal(individual.calls[0].route,"/api/admin/restart");
    assert.deepEqual(JSON.parse(individual.calls[0].options.body),{mode:"service",service});
    assert.equal(individual.calls[0].options.headers["X-CSRF-Token"],"test-csrf");
    assert.equal(individual.id("restart-dialog").open,false);assert.equal(individual.run("restartBusy"),true);
    assert.equal(individual.id("restart-panel").scrollOptions.block,"center","Progress is brought into view after confirmation");
    assert.equal(individual.run('Array.from(restartServiceButtons.values()).every(button=>button.disabled)'),true);
    assert.equal(individual.run("state.view"),"restart");
    if(service==="admin"){
      individual.sandbox.fetch=async()=>({ok:false,status:401,json:async()=>({ok:false,error:"Expired"})});
      await individual.tick();assert.match(individual.id("restart-status").textContent,/sign in again to check/);assert.equal(individual.timers.size,0);
    }else{
      individual.respond(()=>({...job([service],"complete"),mode:"service",service}));await individual.tick();
      assert.equal(individual.run("restartBusy"),false);assert.match(individual.id("restart-status").textContent,/session remains available/);
      assert.equal(individual.run('Array.from(restartServiceButtons.values()).every(button=>!button.disabled)'),true);
    }
  }
  for(const condition of ['settingsData.restart_available=false','state.user.admin=false','settingsSaving=true','updateBusy=true','restartBusy=true','shutdownPending=true']){
    const unavailable=await ready();unavailable.respond(()=>job(["smtp"]));unavailable.run(condition+';refreshRestartControls();');
    assert.equal(unavailable.run('restartServiceButtons.get("smtp").disabled'),true,condition);
    await unavailable.run('restartServiceButtons.get("smtp").fire("click")');await unavailable.id("restart-form").fire("submit");
    assert.equal(unavailable.calls.length,0,"Unavailable or unauthorized module restarts cannot be submitted");
    assert.notEqual(unavailable.id("restart-dialog").open,true);
    if(condition.includes("restart_available"))assert.equal(unavailable.id("restart-unavailable").hidden,false);
  }
  const pendingConfig=await ready();pendingConfig.sandbox.fetch=async()=>({ok:false,status:409,json:async()=>({ok:false,error:"Apply saved configuration before restarting an individual service."})});
  await pendingConfig.run('openRestartDialog("smtp")');await pendingConfig.id("restart-form").fire("submit");
  assert.equal(pendingConfig.id("restart-dialog").open,true);assert.match(pendingConfig.id("restart-dialog-error").textContent,/Apply saved configuration/);assert.equal(pendingConfig.run("restartBusy"),false);
  const translated=await ready();await translated.run('openRestartDialog("smtp")');
  translated.sandbox.PostPlusI18n.t=(text,args={})=>text==="Restart"?"重启":text==="Restart {service}?"?`重启${args.service}？`:text.replace(/\{(\w+)\}/g,(match,name)=>args[name]??match);
  translated.run("renderServiceRestarts();renderRestartDialog();");assert.equal(translated.run('restartServiceButtons.get("smtp").textContent'),"重启");assert.equal(translated.id("restart-dialog-title").textContent,"重启SMTP？");
  const full=await ready();full.respond(()=>job(["auth","storage","smtp","web","admin"]));
  await full.id("restart-open").fire("click");await full.id("restart-form").fire("submit");
  assert.equal(full.calls[0].route,"/api/admin/restart");assert.equal(full.calls[0].options.headers["X-CSRF-Token"],"test-csrf");
  assert.deepEqual(JSON.parse(full.calls[0].options.body),{mode:"all"});
  assert.equal(full.calls.length,1,"Full restart uses saved configuration without saving form edits");
  assert.equal(full.id("restart-dialog").open,false);
  full.sandbox.fetch=async()=>({ok:false,status:401,json:async()=>({ok:false,error:"Expired"})});
  await full.tick();assert.equal(full.run("state.user.username"),"admin@example.com","Expected restart session loss does not force a sign-in loop");
  assert.match(full.id("restart-status").textContent,/sign in again to check/);assert.equal(full.timers.size,0);
  assert.doesNotMatch(full.id("restart-status").textContent,/Services restarted\./,"401 is not readiness confirmation");
  const moved=await ready();moved.sandbox.schedule={...job(["admin"]),admin_url:"https://mail.example.com:8443/"};
  moved.run("startRestart(schedule)");assert.equal(moved.timers.size,0,"A changed administration origin requires an explicit reconnect");
  assert.equal(moved.id("restart-open-admin").href,"https://mail.example.com:8443/");
  assert.match(moved.id("restart-status").textContent,/sign in again to check/);
  const transient=await ready();transient.sandbox.schedule=job();transient.run("startRestart(schedule)");
  transient.sandbox.fetch=async()=>{throw new Error("Connection interrupted");};await transient.tick();
  assert.equal(transient.run("restartBusy"),true);assert.equal(transient.timers.size,1);
  assert.doesNotMatch(transient.id("restart-status").textContent,/services restarted/i);
  transient.respond(()=>job(["smtp","delivery"],"complete"));await transient.tick();assert.equal(transient.run("restartBusy"),false);
  const failed=await ready();failed.sandbox.schedule=job();failed.run("startRestart(schedule)");failed.respond(()=>job(["smtp"],"failed"));await failed.tick();
  assert.equal(failed.id("restart-error").hidden,false);assert.match(failed.id("restart-error").textContent,/Restart failed/);
  const rolledBack=await ready();rolledBack.sandbox.schedule=job();rolledBack.run("startRestart(schedule)");rolledBack.respond(()=>({...job(["smtp"],"failed"),rolled_back:true}));await rolledBack.tick();
  assert.match(rolledBack.id("restart-error").textContent,/previous affected services were restored/);assert.match(rolledBack.id("restart-error").textContent,/Saved changes are still pending/);
  const restored=await ready();restored.sandbox.schedule=job(["admin"],"complete");restored.run("startRestart(schedule,{restored:true})");
  assert.equal(restored.timers.size,0);assert.match(restored.id("restart-status").textContent,/current administration session is available/);
  assert.equal(restored.run("state.view"),"overview","Historical completion does not redirect the administrator");
  await restored.run('switchView("accounts")');assert.equal(restored.id("view-restart").hidden,true);
  const resuming=await ready();resuming.sandbox.schedule=job(["smtp"],"running");resuming.run("startRestart(schedule,{restored:true})");
  assert.equal(resuming.run("state.view"),"restart","An active restored restart opens its progress location");
  const unscheduled=await ready();unscheduled.respond(()=>({ok:true,restart_required:true,restart_available:true,restart_error:"Cannot schedule",...urls}));
  assert.equal(await unscheduled.run("saveSettings()"),true);assert.match(unscheduled.id("settings-success-message").textContent,/could not be scheduled/);assert.equal(unscheduled.timers.size,0);
  const timeout=await ready();timeout.sandbox.schedule=job();timeout.run("startRestart(schedule);restartStarted=Date.now()-90001;");
  timeout.sandbox.fetch=async()=>{throw new Error("Still offline");};await timeout.tick();assert.equal(timeout.timers.size,0);assert.match(timeout.id("restart-status").textContent,/could not be confirmed/);
  for(const stage of ["fetch","json body"]) {
    const hanging=await ready();hanging.sandbox.schedule=job();hanging.run("startRestart(schedule)");
    let signal;const delays=[],originalSetTimeout=hanging.sandbox.setTimeout;
    hanging.sandbox.setTimeout=(callback,delay)=>{delays.push(delay);return originalSetTimeout(callback);};
    hanging.sandbox.fetch=async(route,options)=>{
      signal=options.signal;
      const unfinished=()=>new Promise((resolve,reject)=>signal.addEventListener("abort",()=>reject(new Error("Request aborted")),{once:true}));
      return stage==="fetch"?unfinished():{ok:true,status:200,json:unfinished};
    };
    const polling=hanging.tick();for(let i=0;i<6;i++)await Promise.resolve();
    assert.equal(signal.aborted,false);assert.equal(delays[0],5000,`${stage} timeout is five seconds`);
    await hanging.tick();await polling;
    assert.equal(signal.aborted,true);assert.equal(hanging.timers.size,1,"Aborting clears the request timeout and schedules a retry");
    assert.equal(hanging.run("restartBusy"),true);assert.doesNotMatch(hanging.id("restart-status").textContent,/services restarted/i);
    hanging.run("restartStarted=Date.now()-90001;");const finalPoll=hanging.tick();for(let i=0;i<6;i++)await Promise.resolve();await hanging.tick();await finalPoll;
    assert.equal(hanging.run("restartBusy"),false,`${stage} cannot keep restart controls disabled past the progress limit`);
    assert.equal(hanging.timers.size,0);assert.match(hanging.id("restart-status").textContent,/could not be confirmed/);
  }
  const stale=await ready();stale.sandbox.schedule=job();stale.run("startRestart(schedule)");let resolve;
  stale.sandbox.fetch=async()=>({ok:true,status:200,json:()=>new Promise(done=>{resolve=done;})});
  const pending=stale.tick();for(let i=0;i<6;i++)await Promise.resolve();stale.run("signedOut()");resolve(job(["smtp"],"complete"));await pending;
  assert.equal(stale.id("restart-panel").hidden,true);assert.equal(stale.id("restart-status").textContent,"");assert.equal(stale.timers.size,0,"Logout cancels restart polling and ignores a stale response");
  const staleSave=await ready();let saved;
  staleSave.sandbox.fetch=async()=>({ok:true,status:200,json:()=>new Promise(done=>{saved=done;})});
  const saving=staleSave.run("saveSettings()");for(let i=0;i<6;i++)await Promise.resolve();staleSave.run("signedOut()");saved({ok:true,restart_required:false,restart:job(),...urls});
  assert.equal(await saving,false);assert.equal(staleSave.id("restart-panel").hidden,true);assert.equal(staleSave.timers.size,0);
  console.log("Restart UI checks passed: all 10 individual modules, authorization/busy/fallback controls, localization, selective/full restart, shutdown apply:false, progress, disconnect/session recovery, timeout, and stale responses.");
}
run().catch(error=>{console.error(error);process.exitCode=1;});
