"""Folder, administrator inspection, quota, and draft HTTP contracts."""
import argparse
from pathlib import Path
import secrets
import smtplib
from urllib.parse import urlencode
from integration import Suite, ROOT, PASSWORD


def login(s, service, username):
    status, headers, result = s.http(service, "POST", "/api/login", {"username": username, "password": PASSWORD})
    assert status == 200, result
    return {"Cookie": headers["Set-Cookie"].split(";", 1)[0], "X-CSRF-Token": result["csrf"]}


def run(s):
    for name in ("auth", "storage", "filter", "web", "admin", "smtp"):
        s.start(name)
    admin, user, other = "admin@localhost", "user+tag@localhost", "other@localhost"
    for name in (admin, user, other):
        assert s.rpc("auth", op="create", username=name, password=PASSWORD, admin=name == admin)["ok"]
    a, u, o = login(s,"admin",admin), login(s,"web",user), login(s,"web",other)
    folder_names = {"INBOX", "Sent", "Trash", "Drafts", "Junk", "Archive"}
    assert {f["name"] for f in s.http("web","GET","/api/folders",headers=u)[2]["folders"]} == folder_names
    assert s.http("admin","GET","/api/folders",headers=a)[0] == 404
    assert s.http("admin","POST","/api/drafts",{},a)[0] == 404
    assert s.http("admin","POST","/api/drafts?x=1",{},a)[0] == 404
    assert s.http("web","GET","/api/admin/messages?username="+user,headers=u)[0] == 404
    assert s.http("admin","POST","/api/login",{"username":user,"password":PASSWORD})[0] == 403
    assert s.http("admin","GET","/api/admin/messages?username="+user)[0] == 401

    def mailbox(folder, who=user):
        result=s.http("admin","GET","/api/admin/messages?"+urlencode({"username":who,"folder":folder}),headers=a)
        assert result[0] == 200, result
        return result[2]["messages"]

    payload={"to":[],"subject":"","text":""}
    assert s.http("web","POST","/api/drafts",payload,{"Cookie":u["Cookie"]})[0] == 403
    status,_,draft=s.http("web","POST","/api/drafts",payload,u)
    assert status==200, draft
    draft_id=draft["id"]
    assert mailbox("Drafts")[0]["id"] == draft_id
    assert s.http("web","GET","/api/messages/"+draft_id,headers=o)[0]==404
    assert s.http("web","POST","/api/drafts",dict(payload,id=draft_id),o)[0]==409
    payload.update(id=draft_id,to=[other],subject="Private draft subject",text="Private draft body")
    assert s.http("web","POST","/api/drafts",payload,u)[0]==200
    seen_before=s.rpc("storage",op="get",username=user,id=draft_id)["seen"]
    response=s.http("admin","GET","/api/admin/messages/"+draft_id+"?"+urlencode({"username":user}),headers=a)
    assert response[0]==200 and response[2]["message"]["text"]=="Private draft body",response
    assert s.rpc("storage",op="get",username=user,id=draft_id)["seen"]==seen_before
    incoming=s.rpc("storage",op="deliver",username=user,raw="Subject: Still unread\r\n\r\nIncoming\r\n",delivery_id=secrets.token_hex(12))["id"]
    assert not s.rpc("storage",op="get",username=user,id=incoming)["seen"]
    assert s.http("admin","GET","/api/admin/messages/"+incoming+"?"+urlencode({"username":user}),headers=a)[0]==200
    assert not s.rpc("storage",op="get",username=user,id=incoming)["seen"]
    assert s.http("admin","DELETE","/api/admin/messages/"+draft_id+"?"+urlencode({"username":user}),headers=a)[0] == 405
    status,_,sent=s.http("web","POST","/api/send",dict(to=[other],subject="Private draft subject",text="Private draft body",draft_id=draft_id),u)
    assert status==202,sent
    assert not mailbox("Drafts")
    assert len(mailbox("Sent"))==1
    sent_id=mailbox("Sent")[0]["id"]
    assert sent["sent_id"]==sent_id
    assert s.rpc("storage",op="get",username=user,id=draft_id).get("folder")!="Drafts"
    for folder in ("Archive","Junk","INBOX"):
        assert s.http("web","POST",f"/api/messages/{sent_id}/move",{"folder":folder},u)[0]==200
        assert any(m["id"]==sent_id for m in s.http("web","GET","/api/messages?"+urlencode({"folder":folder}),headers=u)[2]["messages"])
    assert s.http("web","POST",f"/api/messages/{sent_id}/move",{"folder":"invalid"},u)[0]==400
    assert s.http("web","DELETE",f"/api/messages/{sent_id}?permanent=true",headers=u)[0]==409
    assert s.http("web","DELETE",f"/api/messages/{sent_id}",headers=u)[0]==200
    assert mailbox("Trash")[0]["id"]==sent_id
    assert s.http("web","DELETE",f"/api/messages/{sent_id}",headers=u)[0]==200
    assert mailbox("Trash")[0]["id"]==sent_id, "A stale ordinary delete must not erase trash permanently"
    assert s.http("web","DELETE",f"/api/messages/{sent_id}?permanent=true",headers=u)[0]==200
    assert not mailbox("Trash")

    query=urlencode({"username":user})
    assert s.http("admin","POST","/api/admin/quota",{"username":user,"quota_bytes":5*1024**3},a)[0]==200
    quota=s.http("admin","GET","/api/admin/quota?"+query,headers=a)[2]
    assert quota["quota_bytes"]==quota["max_bytes"]==5*1024**3,quota
    assert s.http("admin","POST","/api/admin/quota",{"username":user,"quota_bytes":1},a)[0]==200
    assert s.http("web","POST","/api/drafts",{"to":[],"subject":"quota","text":"full"},u)[0]==409
    assert s.http("admin","POST","/api/admin/quota",{"username":user,"quota_bytes":None},a)[0]==200
    assert s.http("admin","GET","/api/admin/quota?"+query,headers=a)[2]["quota_bytes"] is None
    for value in (0,-1,2**50+1,1.5,"100"):
        assert s.http("admin","POST","/api/admin/quota",{"username":user,"quota_bytes":value},a)[0]==400,value
    for query in ("folder=%00","folder=%zz","folder=INBOX&folder=Sent"):
        assert s.http("web","GET","/api/messages?"+query,headers=u)[0]==400
    # Authenticated SMTP Sent ownership follows the login, never the envelope.
    with smtplib.SMTP("127.0.0.1",s.ports["smtp"],local_hostname="localhost",timeout=10) as smtp:
        smtp.login(user,PASSWORD)
        assert smtp.sendmail(other,[admin],"From: other@localhost\r\nSubject: SMTP sent copy\r\n\r\nHello\r\n")=={}
    assert len(mailbox("Sent"))==1 and not mailbox("Sent",other)
    # ACME control endpoints require both admin session and mutation CSRF.
    assert s.http("admin","GET","/api/admin/acme/status")[0]==401
    assert s.http("admin","POST","/api/admin/acme/start",{}, {"Cookie":a["Cookie"]})[0]==403
    assert s.http("admin","GET","/api/admin/acme/status",headers=a)[2]["state"]=="idle"
    assert s.http("admin","POST","/api/admin/acme/start",{"directory":"https://127.0.0.1/"},a)[0]==400
    logs=s.http("admin","GET","/api/admin/logs?service=admin&limit=100",headers=a)[2]
    assert "Private draft body" not in str(logs) and "Private draft subject" not in str(logs)
    assert any("inspected message" in item["message"] for item in logs["entries"])
    # Large configured global limits roundtrip without truncation or restart.
    settings=s.http("admin","GET","/api/admin/config",headers=a)[2]
    saved=s.http("admin","POST","/api/admin/config",{"revision":settings["revision"],"values":{"max_mailbox_bytes":6*1024**3}},a)
    assert saved[0]==200 and saved[2]["restart_required"],saved
    assert s.http("admin","GET","/api/session",headers=a)[0]==200
    print("PASS mailbox folders, drafts/Sent, admin read-only inspection, audit, personal quotas and ACME authorization",flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir",type=Path,required=True)
    args=parser.parse_args()
    directory=ROOT/"build/test-runs"/("mailbox-web-"+secrets.token_hex(6))
    directory.mkdir(parents=True)
    suite=Suite(args.bin_dir.resolve(),directory)
    try:run(suite)
    finally:suite.close()
