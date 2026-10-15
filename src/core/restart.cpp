#include <postplus/restart.hpp>
#include <postplus/maintenance.hpp>
#include <algorithm>
#include <set>

namespace postplus {
const std::vector<std::string>& supervisor_services() {
    static const std::vector<std::string> services{
        "auth", "storage", "filter", "transfer", "delivery", "smtp", "pop3", "imap", "web", "admin"};
    return services;
}

std::vector<std::string> restart_plan(const Config& running, const Config& saved, const std::string& mode) {
    if (mode == "all") return supervisor_services();
    if (mode != "changed") throw MaintenanceError("Restart mode must be changed or all.", 400);
    std::set<std::string> selected;
    auto add = [&](std::initializer_list<const char*> names) { for (auto name : names) selected.insert(name); };
    auto all = [&] { selected.insert(supervisor_services().begin(), supervisor_services().end()); };
    auto endpoint = [&](const std::string& service) {
        selected.insert(service);
        if (service == "auth") add({"delivery", "smtp", "pop3", "imap", "web", "admin"});
        if (service == "storage") add({"delivery", "smtp", "pop3", "imap", "web", "admin"});
        if (service == "filter") add({"delivery", "web"});
        if (service == "transfer") add({"delivery"});
    };
    // Legacy configurations derive their mode from smarthost_host. A manual
    // edit changing that fallback also changes submission policy and the
    // delivery worker's transfer deadline, even without an outbound_mode field.
    if (running.outbound_mode() != saved.outbound_mode()) add({"transfer", "delivery", "smtp", "web"});
    // Config::from_file resolves paths; compare those normalized values, including
    // values deleted by a manual file edit. Unknown settings restart the group.
    std::set<std::string> keys;
    for (const auto& [key, value] : running.values.items()) keys.insert(key);
    for (const auto& [key, value] : saved.values.items()) keys.insert(key);
    for (const auto& key : keys) {
        if (running.values.contains(key) == saved.values.contains(key) &&
            (!running.values.contains(key) || running.values.at(key) == saved.values.at(key))) continue;
        if (key == "ports") {
            for (const auto& service : supervisor_services())
                if (service != "delivery" && running.port(service) != saved.port(service)) endpoint(service);
            for (const auto* alias : {"submission", "smtps"})
                if (running.port(alias) != saved.port(alias)) endpoint("smtp");
            if (running.port("pop3s") != saved.port("pop3s")) endpoint("pop3");
            if (running.port("imaps") != saved.port("imaps")) endpoint("imap");
        } else if (key == "bind") add({"smtp", "pop3", "imap", "web"});
        else if (key == "admin_bind") add({"admin"});
        else if (key == "tls_certificate" || key == "tls_private_key" || key == "allow_insecure_auth")
            add({"smtp", "pop3", "imap", "web", "admin"});
        else if (key == "web_root" || key == "web_session_seconds" || key == "max_web_sessions") add({"web", "admin"});
        else if (key == "auth_pbkdf2_iterations" || key == "max_password_bytes") add({"auth"});
        else if (key == "max_auth_attempts") add({"smtp", "pop3", "imap"});
        else if (key == "max_recipients" || key == "smtp_data_timeout_seconds") add({"smtp"});
        else if (key == "max_mailbox_bytes" || key == "max_mailbox_messages" ||
                 key == "max_queue_bytes" || key == "max_queue_messages") add({"storage"});
        else if (key == "delivery_lock_port" || key == "delivery_max_age_seconds") add({"delivery"});
        else if (key == "clamav_host" || key == "clamav_port" || key == "clamav_timeout_seconds" ||
                 key == "spam_threshold" || key == "blocked_terms" || key == "spam_rules" ||
                 key == "spam_allow_senders" || key == "spam_block_senders" || key.rfind("rspamd_", 0) == 0) add({"filter"});
        else if (key == "outbound_mode") add({"transfer", "delivery", "smtp", "web"});
        else if (key == "direct_timeout_seconds" || key == "smarthost_timeout_seconds") add({"transfer", "delivery"});
        else if (key == "mail_hostname") add({"transfer", "web", "admin"});
        else if (key == "dkim_selector" || key == "dkim_private_key" ||
                 key == "direct_tls" || key.rfind("smarthost_", 0) == 0) add({"transfer"});
        else if (key == "setup_complete" || key == "setup_required") {}
        else all();
    }
    std::vector<std::string> ordered;
    for (const auto& service : supervisor_services()) if (selected.contains(service)) ordered.push_back(service);
    return ordered;
}
}
