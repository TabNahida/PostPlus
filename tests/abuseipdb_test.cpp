#include <postplus/abuseipdb.hpp>
#include <postplus/access.hpp>
#include <atomic>
#include <condition_variable>
#include <future>
#include <iostream>
#include <mutex>
#include <set>
#include <thread>
#include <sqlite3.h>

using namespace postplus;
namespace {
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class F>void rejects(F action){try{action();}catch(const AbuseError&){return;}throw std::runtime_error("unsafe AbuseIPDB input accepted");}
Json settings(){auto value=abuseipdb_defaults();value["enabled"]=true;value["blacklist_enabled"]=false;value["api_key_env"]="";value["api_key"]="private-test-secret";return value;}
struct FixtureDirectory {
    std::filesystem::path path=std::filesystem::current_path()/"build"/"test-runs"/("abuse-planner-"+random_hex(8));
    FixtureDirectory(){std::filesystem::create_directories(path);}
    ~FixtureDirectory(){std::error_code error;std::filesystem::remove_all(path,error);}
};
void database_edit(const std::filesystem::path& path,const std::string& sql){sqlite3* db=nullptr;const auto text=path.string();check(sqlite3_open(text.c_str(),&db)==SQLITE_OK,"fixture database open failed");const int code=sqlite3_exec(db,sql.c_str(),nullptr,nullptr,nullptr);sqlite3_close(db);check(code==SQLITE_OK,"fixture database edit failed");}
}
int main(){try{
    auto config=settings();
    check(!abuseipdb_defaults().at("enabled").get<bool>(),"integration enabled by default");
    check(abuseipdb_defaults().at("cache_seconds")==86400&&abuseipdb_defaults().at("blacklist_refresh_seconds")==21600,"free-account defaults missing");
    auto legacy=config;legacy["cache_seconds"]=3600;legacy.erase("automatic_check_budget");check(validate_abuseipdb_settings(legacy,Json::object()).at("cache_seconds")==3600,"legacy cache setting was overwritten");
    rejects([&]{validate_abuseipdb_settings(config,{{"api_key","oops\r\nInjected: true"}});});
    rejects([&]{validate_abuseipdb_settings(config,{{"verification_token","<script>bad</script>"}});});
    rejects([&]{validate_abuseipdb_settings(config,{{"verification_token","abuseipdb-verification-"}});});
    rejects([&]{validate_abuseipdb_settings(config,{{"score_threshold",true}});});
    rejects([&]{validate_abuseipdb_settings(config,{{"score_threshold",101}});});
    rejects([&]{validate_abuseipdb_settings(config,{{"report_cooldown_seconds",1}});});
    check(validate_abuseipdb_settings(config,{{"api_key",""}}).at("api_key")==config.at("api_key"),"empty key overwrote secret");
    check(validate_abuseipdb_settings(config,{{"clear_api_key",true}}).at("api_key")=="","key clearing failed");
    for(const auto* address:{"127.0.0.1","10.0.0.1","::1","192.0.2.1","http://example.org","::ffff:127.0.0.1"})
        rejects([&]{abuseipdb_request("check",{{"ipAddress",address}});});
    auto request=abuseipdb_request("check",{{"ipAddress","2606:4700:4700::1111"},{"verbose",true}});
    check(request.method=="GET" && request.target.find("2606%3A4700")!=std::string::npos && request.target.find("verbose=")!=std::string::npos,"IPv6 check encoding failed");
    request=abuseipdb_request("report",{{"ip","8.8.8.8"},{"categories",Json::array({18})},{"comment","Local brute force & evidence"}});
    check(request.method=="POST" && request.body.find("%26")!=std::string::npos,"report encoding failed");
    check(abuseipdb_request("clear-address",{{"ipAddress","8.8.8.8"}}).method=="DELETE","clear-address did not use DELETE");
    check(abuseipdb_request("blacklist",Json::object()).target.find("confidenceMinimum=100")!=std::string::npos,"default blacklist required a subscriber threshold");
    rejects([&]{abuseipdb_request("report",{{"ip","8.8.8.8"},{"categories",Json::array({99})},{"comment","bad category"}});});
    rejects([&]{abuseipdb_request("check",{{"ipAddress","8.8.8.8"},{"key","injected"}});});
    rejects([&]{abuseipdb_request("check-block",{{"network","8.0.0.0/1"}});});
    request=abuseipdb_request("bulk-report",{{"reports",Json::array({{{"ip","8.8.8.8"},{"categories",Json::array({18})},{"comment","local \"attack\", log"},{"timestamp","2026-10-25T00:00:00Z"}}})}});
    check(request.content_type.starts_with("multipart/form-data; boundary=") && request.body.find("name=\"csv\"")!=std::string::npos && request.body.find("IP,Categories,ReportDate,Comment")!=std::string::npos && request.body.find("\"\"attack\"\"")!=std::string::npos,"bulk CSV formatting failed");
    std::atomic<int> calls{0};
    AbuseIpDb client([&](const AbuseHttpRequest&,const std::string& key,auto){
        check(key=="private-test-secret","secret not passed in header transport");++calls;
        return AbuseHttpResponse{200,{{"x-ratelimit-limit","1000"},{"x-ratelimit-remaining","999"},{"x-ratelimit-reset","4000000000"}},R"({"data":{"ipAddress":"8.8.8.8","isPublic":true,"abuseConfidenceScore":95,"totalReports":20}})"};
    });
    client.configure(config);
    check(client.view().dump().find("private-test-secret")==std::string::npos,"secret leaked in view");
    check(client.view().at("quotas").at(3).at("limit").is_null(),"unknown quota fabricated");
    auto result=client.perform("check",{{"ipAddress","8.8.8.8"}});
    check(result.at("ok").get<bool>() && result.at("quotas").at(3).at("used")==1,"quota headers not respected");
    config["auto_ban"]=true;client.configure(config);
    check(client.reputation("8.8.8.8").has_value(),"lookup missing");const int cached_calls=calls;
    check(client.reputation("8.8.8.8").has_value() && calls==cached_calls,"lookup cache missed");
    check(!client.reputation("127.0.0.1"),"private address contacted upstream");
    result=client.perform("bulk-check",{{"ips",Json::array({"8.8.8.8","8.8.8.8","1.1.1.1"})}});
    check(result.at("data").size()==2 && calls==cached_calls+2,"bulk-check did not deduplicate or used nonexistent endpoint");
    check(result.at("meta").at("requested")==2 && result.at("meta").at("completed")==2 && result.at("meta").at("incomplete")==false,"complete batch metadata missing");
    check(result.at("quotas").at(2).at("supported")==false && result.at("quotas").at(2).at("limit").is_null(),"bulk-check quota invented");
    std::atomic<int> limited_calls{0};AbuseIpDb limited([&](const auto&,const auto&,auto){++limited_calls;return AbuseHttpResponse{429,{{"retry-after","3600"},{"x-ratelimit-limit","1000"},{"x-ratelimit-remaining","0"}},"{}"};});limited.configure(config);
    check(limited.perform("check",{{"ipAddress","8.8.8.8"}}).at("status")==429,"429 missing");
    check(limited.perform("check",{{"ipAddress","1.1.1.1"}}).at("status")==429 && limited_calls==1,"backoff did not stop quota requests");
    result=limited.perform("bulk-check",{{"ips",Json::array({"8.8.8.8","1.1.1.1"})}});
    check(result.at("meta").at("requested")==2 && result.at("meta").at("completed")==1 && result.at("meta").at("incomplete")==true && limited_calls==1,"rate-limited batch did not expose partial results");
    {
        std::promise<void> started,release;
        auto released=release.get_future().share();std::atomic<int> concurrent_calls{0};
        AbuseIpDb concurrent([&](const auto&,const auto&,auto deadline){
            check(deadline<=std::chrono::steady_clock::now()+std::chrono::seconds(4),"request exceeded its per-call deadline");
            if(++concurrent_calls==1) {
                started.set_value();released.wait_for(std::chrono::seconds(2));
                return AbuseHttpResponse{200,{{"x-ratelimit-limit","1000"},{"x-ratelimit-remaining","1"}},R"({"data":{}})"};
            }
            return AbuseHttpResponse{429,{{"retry-after","3600"},{"x-ratelimit-limit","1000"},{"x-ratelimit-remaining","0"}},"{}"};
        });
        concurrent.configure(config);
        auto older=std::async(std::launch::async,[&]{return concurrent.perform("check",{{"ipAddress","8.8.8.8"}});});
        const auto began=started.get_future().wait_for(std::chrono::seconds(2));
        if(began!=std::future_status::ready){release.set_value();check(false,"concurrent quota fixture failed to start");}
        const auto newer=concurrent.perform("check",{{"ipAddress","1.1.1.1"}});
        release.set_value();const auto old=older.get();
        check(newer.at("status")==429 && old.at("ok").get<bool>(),"concurrent quota fixture responses changed");
        check(concurrent.perform("check",{{"ipAddress","8.8.4.4"}}).at("status")==429 && concurrent_calls==2,"older successful response cleared newer exhausted quota");
    }
    AbuseIpDb outage([](const auto&,const auto&,auto)->AbuseHttpResponse{throw std::runtime_error("secret should not leak");});outage.configure(config);
    check(!outage.reputation("8.8.8.8"),"outage did not fail open");
    check(outage.perform("check",{{"ipAddress","8.8.8.8"}}).dump().find("secret should not leak")==std::string::npos,"upstream exception leaked");
    std::mutex mutex;std::condition_variable completed;int reports=0;std::string comment;
    {AbuseIpDb reporter([&](const AbuseHttpRequest& req,const auto&,auto){std::lock_guard lock(mutex);++reports;comment=req.body;completed.notify_one();return AbuseHttpResponse{200,{},R"({"data":{"ipAddress":"8.8.8.8"}})"};});
        config["auto_report"]=true;config["auto_ban"]=false;reporter.configure(config);
        reporter.observe_failures("8.8.8.8","imap",9);reporter.observe_failures("127.0.0.1","imap",99);
        reporter.observe_failures("8.8.8.8","imap",10);reporter.observe_failures("8.8.8.8","imap",11);
        std::unique_lock lock(mutex);check(completed.wait_for(lock,std::chrono::seconds(2),[&]{return reports==1;}),"automatic report missing");
        check(comment.find("10%20failed%20authentication")!=std::string::npos,"report lacked local evidence");
    }
    check(reports==1,"report cooldown failed");
    std::atomic<int> background_calls{0};
    AbuseIpDb background([&](const AbuseHttpRequest& req,const auto&,auto){check(req.target.starts_with("check?"),"background task used wrong endpoint");++background_calls;return AbuseHttpResponse{200,{},R"({"data":{"ipAddress":"8.8.8.8","isPublic":true,"abuseConfidenceScore":98,"totalReports":42}})"};});
    config["auto_ban"]=true;config["auto_report"]=false;background.configure(config);
    check(!background.reputation("8.8.8.8",true) && background_calls==0,"admission made network request");
    background.observe_failures("8.8.8.8","imap",1);
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
    while(!background.reputation("8.8.8.8",true) && std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(1));
    check(background.reputation("8.8.8.8",true).has_value() && background_calls==1,"failed sign-in did not cache background intelligence");
    check(required_api_permission("POST","/api/admin/abuseipdb/check")=="security:read","read permission missing");
    check(required_api_permission("POST","/api/admin/abuseipdb/report")=="security:write","write permission missing");
    check(required_api_permission("POST","/api/admin/abuseipdb/quotas/refresh")=="security:write","quota refresh must require write permission");
    {
        int probes=0;std::set<std::string> queried;
        AbuseIpDb capacity([&](const AbuseHttpRequest& request,const auto& key,auto deadline){
            check(request.method=="GET" && request.body.empty(),"capacity discovery performed a mutation");
            check(key=="private-test-secret","quota probe used a different secret");
            check(deadline<=std::chrono::steady_clock::now()+std::chrono::seconds(4),"quota probe lacks bounded deadline");
            queried.insert(request.target.substr(0,request.target.find('?')));++probes;
            return AbuseHttpResponse{200,{{"x-ratelimit-limit","1000"},{"x-ratelimit-remaining","999"}},R"({"data":{}})"};
        });
        auto disabled=settings();disabled["enabled"]=false;capacity.configure(disabled);
        check(capacity.perform("check",{{"ipAddress","8.8.8.8"}}).at("code")=="abuseipdb_not_configured","ordinary requests bypassed disabled state");
        const auto discovered=capacity.refresh_quotas();
        check(discovered.at("status")=="complete" && probes==4 && queried==std::set<std::string>{"check","reports","blacklist","check-block"},"quota discovery did not use exactly four safe read endpoints");
        check(!capacity.settings().at("enabled").get<bool>(),"quota refresh enabled protection");
        check(capacity.refresh_quotas().at("status")=="cooldown" && probes==4,"capacity refresh repeated scarce API requests");
        const auto capacity_view=capacity.view();
        for(const auto& row:capacity_view.at("quotas"))if(row.at("endpoint")=="report" || row.at("endpoint")=="bulk-report" || row.at("endpoint")=="clear-address")
            check(row.at("limit").is_null() && row.at("used").is_null(),"mutation-only quota was invented");
        disabled["api_key"]="";capacity.configure(disabled);
        check(capacity.refresh_quotas().at("status")=="not_configured" && probes==4,"key removal left quota probing enabled");
    }
    {
        int probes=0;AbuseIpDb invalid_key([&](const auto&,const auto&,auto){++probes;return AbuseHttpResponse{401,{},"{}"};});
        invalid_key.configure(settings());
        check(invalid_key.refresh_quotas().at("status")=="failed" && probes==1,"invalid key spent additional endpoint requests");
        check(invalid_key.view().at("api_key_configured")==true,"quota failure deleted the saved key");
    }
    {
        int probes=0;AbuseIpDb no_budget([&](const auto&,const auto&,auto){++probes;return AbuseHttpResponse{};});no_budget.configure(settings());
        const auto budget_result=no_budget.refresh_quotas(std::chrono::milliseconds(0));
        check(budget_result.at("status")=="failed" && probes==0,"zero budget sent an upstream request");
        for(const auto& probe:budget_result.at("probes"))check(probe.at("code")=="skipped","expired probe not marked skipped");
    }
    {
        std::promise<void> began,release;auto released=release.get_future().share();std::atomic<int> newer_calls{0};
        AbuseIpDb rotated([&](const auto&,const std::string& key,auto){
            if(key=="private-test-secret"){began.set_value();released.wait_for(std::chrono::seconds(2));}
            else{check(key=="replacement-secret","unexpected rotated key");++newer_calls;}
            return AbuseHttpResponse{200,{{"x-ratelimit-limit",key=="private-test-secret"?"1000":"3000"},{"x-ratelimit-remaining","2999"}},R"({"data":{}})"};
        });
        auto configured=settings();rotated.configure(configured);
        auto old=std::async(std::launch::async,[&]{return rotated.refresh_quotas();});
        if(began.get_future().wait_for(std::chrono::seconds(2))!=std::future_status::ready){release.set_value();check(false,"old key probe failed to start");}
        check(rotated.refresh_quotas().at("status")=="busy","same-key refresh was not deduplicated");
        configured["api_key"]="replacement-secret";rotated.configure(configured);
        const auto next=rotated.refresh_quotas();release.set_value();const auto stale=old.get();
        check(next.at("status")=="complete" && newer_calls==4,"rotated key could not discover its own capacities");
        check(stale.at("status")=="settings_changed","old-key refresh overwrote current state");
        check(rotated.view().at("quota_refresh").at("status")=="complete","old refresh discarded new-key observations");
    }
    {
        std::promise<void> release;auto released=release.get_future().share();std::atomic<int> active_calls{0};
        AbuseIpDb occupied([&](const auto&,const auto&,auto){++active_calls;released.wait_for(std::chrono::seconds(2));return AbuseHttpResponse{200,{{"x-ratelimit-limit","1000"},{"x-ratelimit-remaining","998"}},R"({"data":{}})"};});occupied.configure(settings());
        auto first=std::async(std::launch::async,[&]{return occupied.perform("check",{{"ipAddress","8.8.8.8"}});});
        auto second=std::async(std::launch::async,[&]{return occupied.perform("reports",{{"ipAddress","8.8.8.8"}});});
        const auto occupied_deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while(active_calls<2 && std::chrono::steady_clock::now()<occupied_deadline)std::this_thread::sleep_for(std::chrono::milliseconds(1));
        if(active_calls!=2){release.set_value();check(false,"fixture failed to occupy upstream slots");}
        const auto busy=occupied.refresh_quotas();release.set_value();first.get();second.get();
        check(busy.at("status")=="busy" && busy.at("checked_at").is_null(),"unsent quota probes entered cooldown");
        check(occupied.refresh_quotas().at("status")=="complete","capacity remained blocked after request slots freed");
    }
    {
        FixtureDirectory directory;const auto database=directory.path/"auth.sqlite3";int calls=0;
        auto budgeted=settings();budgeted["automatic_check_budget"]=2;
        auto transport=[&](const auto&,const auto&,auto){++calls;return AbuseHttpResponse{200,{},R"({"data":{"ipAddress":"8.8.8.8","isPublic":true,"abuseConfidenceScore":99,"totalReports":20}})"};};
        {AbuseIpDb first(transport,database);first.configure(budgeted);check(first.perform("check",{{"ipAddress","8.8.8.8"}}).at("ok").get<bool>(),"manual check failed");}
        {AbuseIpDb restarted(transport,database);restarted.configure(budgeted);budgeted["auto_ban"]=true;restarted.configure(budgeted);check(restarted.reputation("8.8.8.8").has_value(),"remaining automatic budget was lost");check(!restarted.reputation("1.1.1.1")&&calls==2,"restart reset automatic daily budget");check(restarted.perform("check",{{"ipAddress","1.1.1.1"}}).at("ok").get<bool>()&&calls==3,"manual action could not use reserved headroom");budgeted["api_key"]="replacement-secret";restarted.configure(budgeted);check(!restarted.reputation("8.8.4.4")&&calls==3,"key rotation replenished same-account daily budget");check(restarted.view().at("automation").at("budgets").at("check").at("used")==3,"local reservations not exposed separately");}
        database_edit(database,"UPDATE abuseipdb_daily_usage SET day=day-1;");
        {AbuseIpDb next_day(transport,database);next_day.configure(budgeted);check(next_day.reputation("8.8.8.8").has_value()&&calls==4,"previous UTC day consumed current-day budget");}
    }
    {
        int calls=0;AbuseIpDb headroom([&](const auto&,const auto&,auto){++calls;return AbuseHttpResponse{200,{{"x-ratelimit-limit","1000"},{"x-ratelimit-remaining","200"}},R"({"data":{"ipAddress":"8.8.8.8","isPublic":true,"abuseConfidenceScore":99,"totalReports":20}})"};});
        auto config=settings();config["auto_ban"]=true;headroom.configure(config);headroom.perform("check",{{"ipAddress","8.8.8.8"}});check(!headroom.reputation("1.1.1.1")&&calls==1,"automation spent observed twenty-percent reserve");headroom.perform("check",{{"ipAddress","1.1.1.1"}});check(calls==2,"explicit action could not use actual remaining quota");
    }
    {
        FixtureDirectory directory;const auto database=directory.path/"auth.sqlite3";std::atomic<int> blacklist_calls{0},events{0};
        auto config=settings();config["enabled"]=false;config["auto_ban"]=true;config["blacklist_enabled"]=true;
        auto transport=[&](const AbuseHttpRequest& request,const auto&,auto){if(request.target.starts_with("blacklist?")){++blacklist_calls;return AbuseHttpResponse{200,{{"x-ratelimit-limit","5"},{"x-ratelimit-remaining",std::to_string(5-blacklist_calls.load())}},request.target.find("limit=10000")!=request.target.npos?R"({"data":[{"ipAddress":"8.8.4.4","abuseConfidenceScore":100}]})":R"({"data":[{"ipAddress":"1.1.1.1","abuseConfidenceScore":100}]})"};}return AbuseHttpResponse{200,{{"x-ratelimit-limit","1000"},{"x-ratelimit-remaining","999"}},R"({"data":{}})"};};
        {AbuseIpDb scheduled(transport,database);scheduled.set_event_sink([&](Json event){if(event.at("kind")=="abuseipdb_blacklist"&&event.at("outcome")=="success")++events;});scheduled.configure(config);scheduled.refresh_quotas();check(blacklist_calls==1&&!scheduled.blacklisted("1.1.1.1"),"quota probe installed a truncated security cache");config["enabled"]=true;scheduled.configure(config);const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(4);while(!scheduled.blacklisted("8.8.4.4")&&std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(2));check(scheduled.blacklisted("8.8.4.4")&&blacklist_calls==2,"capacity probe prevented initial full sync");scheduled.perform("blacklist",{{"limit",1}});check(scheduled.blacklisted("8.8.4.4")&&!scheduled.blacklisted("1.1.1.1"),"manual small blacklist replaced full security cache");check(scheduled.view().at("automation").at("budgets").at("blacklist").at("used")==3,"blacklist probe and manual call escaped daily count");}
        const auto before=blacklist_calls.load();
        {AbuseIpDb restored(transport,database);restored.configure(config);const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);while(!restored.blacklisted("8.8.4.4")&&std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(std::chrono::milliseconds(2));check(restored.blacklisted("8.8.4.4")&&blacklist_calls==before,"restart lost full cache or repeated scheduled request");config["api_key"]="replacement-secret";restored.configure(config);check(!restored.blacklisted("8.8.4.4"),"key rotation retained old-key list");}
        check(events==1,"scheduled refresh outcome event missing");
    }
    {
        FixtureDirectory directory;const auto database=directory.path/"auth.sqlite3";std::promise<void> started,release;auto released=release.get_future().share();std::atomic<int> full_calls{0};
        auto scheduled_config=settings();scheduled_config["auto_ban"]=true;scheduled_config["blacklist_enabled"]=true;
        AbuseIpDb rotating([&](const AbuseHttpRequest& request,const std::string& key,auto){check(request.target.starts_with("blacklist?"),"rotation fixture made unrelated request");++full_calls;if(key=="private-test-secret"){started.set_value();released.wait_for(std::chrono::seconds(3));return AbuseHttpResponse{200,{},R"({"data":[{"ipAddress":"8.8.4.4","abuseConfidenceScore":100}]})"};}return AbuseHttpResponse{200,{},R"({"data":[{"ipAddress":"1.1.1.1","abuseConfidenceScore":100}]})"};},database);
        rotating.configure(scheduled_config);if(started.get_future().wait_for(std::chrono::seconds(3))!=std::future_status::ready){release.set_value();check(false,"scheduled rotation fixture failed to start");}
        sqlite3* blocker=nullptr;check(sqlite3_open(database.string().c_str(),&blocker)==SQLITE_OK,"rotation fixture database open failed");check(sqlite3_exec(blocker,"BEGIN IMMEDIATE",nullptr,nullptr,nullptr)==SQLITE_OK,"rotation fixture could not hold cache write");release.set_value();std::this_thread::sleep_for(std::chrono::milliseconds(25));scheduled_config["api_key"]="replacement-secret";rotating.configure(scheduled_config);sqlite3_exec(blocker,"COMMIT",nullptr,nullptr,nullptr);sqlite3_close(blocker);
        const auto rotation_deadline=std::chrono::steady_clock::now()+std::chrono::seconds(4);while(!rotating.blacklisted("1.1.1.1")&&std::chrono::steady_clock::now()<rotation_deadline)std::this_thread::sleep_for(std::chrono::milliseconds(2));check(rotating.blacklisted("1.1.1.1")&&!rotating.blacklisted("8.8.4.4")&&full_calls==2,"old-key success delayed or replaced the new-key full cache");
        scheduled_config["enabled"]=false;rotating.configure(scheduled_config);check(!rotating.blacklisted("1.1.1.1"),"disabled policy honored cached blacklist");
    }
    {
        FixtureDirectory directory;const auto database=directory.path/"auth.sqlite3";auto strict=settings();strict["auto_ban"]=true;strict["blacklist_enabled"]=true;
        std::atomic<int> rejected_lists{0};AbuseIpDb invalid_list([&](const auto&,const auto&,auto){++rejected_lists;return AbuseHttpResponse{200,{},R"({"data":[{"ipAddress":"8.8.8.8","abuseConfidenceScore":100},{"ipAddress":"127.0.0.1","abuseConfidenceScore":100}]})"};},database);invalid_list.configure(strict);
        const auto invalid_deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);while(rejected_lists==0&&std::chrono::steady_clock::now()<invalid_deadline)std::this_thread::sleep_for(std::chrono::milliseconds(2));std::this_thread::sleep_for(std::chrono::milliseconds(10));check(!invalid_list.blacklisted("8.8.8.8")&&!invalid_list.blacklisted("127.0.0.1"),"partly invalid provider list was installed");
    }
    check(!required_api_permission("POST","/api/admin/abuseipdb/unknown"),"unknown endpoint permitted");
    std::cout<<"AbuseIPDB request validation, quotas, caching, backoff, report evidence and permissions passed\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
