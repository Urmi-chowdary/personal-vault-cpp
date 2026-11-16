#ifndef CONSENTMANAGER_H
#define CONSENTMANAGER_H

#include <ctime>
#include <string>
#include <vector>
#include "AuditLogger.h"

struct ConsentRecord {
    std::string app;
    std::string permission;
    bool granted;
    std::time_t when;
};

// Records the user's grant / deny / revoke decisions. The latest record wins.
class ConsentManager {
private:
    std::vector<ConsentRecord> records;
    AuditLogger& audit;          // collaborates with the logger

public:
    explicit ConsentManager(AuditLogger& audit);

    void decide(const std::string& app, const std::string& permission, bool granted);
    bool revoke(const std::string& app, const std::string& permission);
    bool isGranted(const std::string& app, const std::string& permission) const;
    bool hasDecision(const std::string& app, const std::string& permission) const;

    const std::vector<ConsentRecord>& all() const;
    void addLoaded(const ConsentRecord& r);   // used when loading from file
    void clear();
    void show() const;
};

#endif
