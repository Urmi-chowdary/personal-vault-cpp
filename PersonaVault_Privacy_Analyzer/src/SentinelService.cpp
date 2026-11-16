#include "SentinelService.h"
#include "Utils.h"
#include <algorithm>
#include <stdexcept>

SentinelService::SentinelService() : audit("audit_log.txt"), consents(audit) {}

AppClient* SentinelService::findApp(const std::string& name) {
    for (auto& a : apps) if (a.getName() == name) return &a;
    return nullptr;
}

const AppClient* SentinelService::findApp(const std::string& name) const {
    for (const auto& a : apps) if (a.getName() == name) return &a;
    return nullptr;
}

void SentinelService::registerApp(const std::string& name, const std::string& purpose,
                                  const std::vector<std::string>& permissions) {
    if (name.empty()) throw std::invalid_argument("App name cannot be empty");
    if (name.find('|') != std::string::npos)
        throw std::invalid_argument("App name cannot contain '|'");
    if (findApp(name)) throw std::invalid_argument("App already registered");
    if (!AppClient::isValidPurpose(purpose)) throw std::invalid_argument("Unknown purpose");
    AppClient app(name, purpose);
    for (const auto& p : permissions) if (!p.empty()) app.addPermission(p);
    apps.push_back(app);
    audit.record("APP REGISTERED: " + name + " (" + purpose + ")");
}

bool SentinelService::removeApp(const std::string& name) {
    auto it = std::find_if(apps.begin(), apps.end(),
        [&](const AppClient& a) { return a.getName() == name; });
    if (it == apps.end()) return false;
    apps.erase(it);
    audit.record("APP REMOVED: " + name);
    return true;
}

std::string SentinelService::metaJson() const {
    std::string j = "{\"purposes\":[";
    const auto& pv = AppClient::validPurposes();
    for (std::size_t i = 0; i < pv.size(); ++i) j += (i ? "," : "") + std::string("\"") + pv[i] + "\"";
    j += "],\"permissions\":[";
    bool first = true;
    for (const auto& kv : DataAsset::catalogue()) {
        if (!first) j += ",";
        first = false;
        j += "{\"name\":\"" + kv.first + "\",\"sensitivity\":" + std::to_string(kv.second) + "}";
    }
    return j + "]}";
}

std::string SentinelService::appJson(const AppClient& app) const {
    std::vector<Finding> findings = engine.evaluate(app);
    int s = scorer.score(findings);
    std::string j = "{\"name\":\"" + jsonEscape(app.getName()) + "\",\"purpose\":\"" +
                    jsonEscape(app.getPurpose()) + "\",\"score\":" + std::to_string(s) +
                    ",\"level\":\"" + scorer.level(s) + "\",\"permissions\":[";
    const auto& perms = app.getPermissions();
    for (std::size_t i = 0; i < perms.size(); ++i) {
        std::string state = "none";
        if (consents.hasDecision(app.getName(), perms[i].getName()))
            state = consents.isGranted(app.getName(), perms[i].getName()) ? "granted" : "denied";
        if (i) j += ",";
        j += "{\"name\":\"" + perms[i].getName() + "\",\"sensitivity\":" +
             std::to_string(perms[i].getSensitivity()) + ",\"consent\":\"" + state + "\"}";
    }
    return j + "]}";
}

std::string SentinelService::appsJson() const {
    std::string j = "[";
    for (std::size_t i = 0; i < apps.size(); ++i) j += (i ? "," : "") + appJson(apps[i]);
    return j + "]";
}

std::string SentinelService::reportJson(const std::string& name) const {
    const AppClient* app = findApp(name);
    if (!app) throw std::invalid_argument("App not found");
    std::vector<Finding> findings = engine.evaluate(*app);
    std::string j = "{\"app\":" + appJson(*app) + ",\"findings\":[";
    for (std::size_t i = 0; i < findings.size(); ++i) {
        if (i) j += ",";
        j += "{\"rule\":\"" + findings[i].rule + "\",\"points\":" + std::to_string(findings[i].points) +
             ",\"explanation\":\"" + jsonEscape(findings[i].explanation) + "\"}";
    }
    j += "],\"removals\":[";
    std::vector<std::string> rem = scorer.safeRemovals(findings);
    for (std::size_t i = 0; i < rem.size(); ++i) j += (i ? "," : "") + std::string("\"") + rem[i] + "\"";
    return j + "]}";
}

std::string SentinelService::auditJson() const {
    std::string j = "[";
    const auto& e = audit.getEntries();
    std::size_t start = e.size() > 60 ? e.size() - 60 : 0;      // newest 60 entries
    for (std::size_t i = e.size(); i > start; --i) {
        if (i != e.size()) j += ",";
        j += "\"" + jsonEscape(e[i - 1]) + "\"";
    }
    return j + "]";
}

void SentinelService::decide(const std::string& app, const std::string& permission, bool granted) {
    const AppClient* a = findApp(app);
    if (!a || !a->hasPermission(permission)) throw std::invalid_argument("App or permission not found");
    consents.decide(app, permission, granted);
}

bool SentinelService::revoke(const std::string& app, const std::string& permission) {
    return consents.revoke(app, permission);
}

std::vector<std::string> SentinelService::applySaferConfig(const std::string& name) {
    AppClient* app = findApp(name);
    if (!app) throw std::invalid_argument("App not found");
    std::vector<std::string> removals = scorer.safeRemovals(engine.evaluate(*app));
    for (const auto& p : removals) {
        app->removePermission(p);
        consents.revoke(name, p);
        audit.record("SAFER CONFIG: removed " + p + " from " + name);
    }
    return removals;
}

void SentinelService::save() {
    storage.saveApps(apps);
    storage.saveConsents(consents);
    audit.record("DATA SAVED");
}

void SentinelService::load() {
    apps = storage.loadApps();
    storage.loadConsents(consents);
    audit.record("DATA LOADED");
}
