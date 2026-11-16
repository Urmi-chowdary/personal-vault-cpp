#ifndef SENTINELSERVICE_H
#define SENTINELSERVICE_H

#include <string>
#include <vector>
#include "AppClient.h"
#include "PolicyEngine.h"
#include "RiskScorer.h"
#include "AuditLogger.h"
#include "ConsentManager.h"
#include "FileStorage.h"

// The application core used by the web server. It owns every Sentinel module
// and exposes simple operations that return JSON text.
class SentinelService {
private:
    std::vector<AppClient> apps;
    PolicyEngine engine;
    RiskScorer scorer;
    AuditLogger audit;
    ConsentManager consents;
    FileStorage storage;

    AppClient* findApp(const std::string& name);
    const AppClient* findApp(const std::string& name) const;
    std::string appJson(const AppClient& app) const;

public:
    SentinelService();

    void registerApp(const std::string& name, const std::string& purpose,
                     const std::vector<std::string>& permissions);
    bool removeApp(const std::string& name);

    std::string metaJson() const;                       // purposes + permission list
    std::string appsJson() const;
    std::string reportJson(const std::string& name) const;
    std::string auditJson() const;

    void decide(const std::string& app, const std::string& permission, bool granted);
    bool revoke(const std::string& app, const std::string& permission);
    std::vector<std::string> applySaferConfig(const std::string& name);

    void save();
    void load();
};

#endif
