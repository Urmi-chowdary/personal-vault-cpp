#include "ConsentManager.h"
#include "Utils.h"
#include <iostream>

ConsentManager::ConsentManager(AuditLogger& audit) : audit(audit) {}

void ConsentManager::decide(const std::string& app, const std::string& permission, bool granted) {
    records.push_back({app, permission, granted, std::time(nullptr)});
    audit.record(std::string(granted ? "CONSENT GRANTED: " : "CONSENT DENIED: ") +
                 permission + " for app " + app);
}

bool ConsentManager::isGranted(const std::string& app, const std::string& permission) const {
    for (auto it = records.rbegin(); it != records.rend(); ++it)
        if (it->app == app && it->permission == permission) return it->granted;
    return false;
}

bool ConsentManager::hasDecision(const std::string& app, const std::string& permission) const {
    for (const auto& r : records)
        if (r.app == app && r.permission == permission) return true;
    return false;
}

bool ConsentManager::revoke(const std::string& app, const std::string& permission) {
    if (!isGranted(app, permission)) return false;
    records.push_back({app, permission, false, std::time(nullptr)});
    audit.record("CONSENT REVOKED: " + permission + " for app " + app);
    return true;
}

const std::vector<ConsentRecord>& ConsentManager::all() const { return records; }
void ConsentManager::addLoaded(const ConsentRecord& r) { records.push_back(r); }
void ConsentManager::clear() { records.clear(); }

void ConsentManager::show() const {
    if (records.empty()) { std::cout << "No consent decisions yet.\n"; return; }
    for (const auto& r : records)
        std::cout << formatTime(r.when) << " | " << r.app << " | " << r.permission
                  << " | " << (r.granted ? "GRANTED" : "DENIED/REVOKED") << "\n";
}
