#ifndef MENUINTERFACE_H
#define MENUINTERFACE_H

#include <string>
#include <vector>
#include "AppClient.h"
#include "PolicyEngine.h"
#include "RiskScorer.h"
#include "AuditLogger.h"
#include "ConsentManager.h"
#include "FileStorage.h"
#include "ReportGenerator.h"

// Console user interface. Ties all modules together.
class MenuInterface {
private:
    std::vector<AppClient> apps;
    PolicyEngine engine;
    RiskScorer scorer;
    AuditLogger audit;
    ConsentManager consents;
    FileStorage storage;
    ReportGenerator reporter;

    AppClient* findApp(const std::string& name);
    std::string ask(const std::string& prompt) const;
    int askInt(const std::string& prompt) const;

    void registerApp();
    void listApps() const;
    void analyzeApp();
    void decidePermissions();
    void applySaferConfig();
    void revokeConsent();
    void saveAll();
    void loadAll();

public:
    MenuInterface();
    void run();
};

#endif
