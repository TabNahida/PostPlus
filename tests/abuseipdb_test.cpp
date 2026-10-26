#include <postplus/abuseipdb.hpp>
#include <postplus/access.hpp>
#include <atomic>
#include <condition_variable>
#include <future>
#include <iostream>
#include <mutex>
#include <set>
#include <thread>

using namespace postplus;
namespace {
void check(bool value,const char* message){if(!value)throw std::runtime_error(message);}
template<class F>void rejects(F action){try{action();}catch(const AbuseError&){return;}throw std::runtime_error("unsafe AbuseIPDB input accepted");}
Json settings(){auto value=abuseipdb_defaults();value["enabled"]=true;value["api_key_env"]="";value["api_key"]="private-test-secret";return value;}
}
int main(){try{
    auto config=settings();
    check(!abuseipdb_defaults().at("enabled").get<bool>(),"integration enabled by default");
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
    check(!required_api_permission("POST","/api/admin/abuseipdb/unknown"),"unknown endpoint permitted");
    std::cout<<"AbuseIPDB request validation, quotas, caching, backoff, report evidence and permissions passed\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
