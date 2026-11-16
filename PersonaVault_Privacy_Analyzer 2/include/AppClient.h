#ifndef APPCLIENT_H
#define APPCLIENT_H

#include <string>
#include <vector>
#include "PermissionRequest.h"

// An application that asks for permissions to personal data.
class AppClient {
private:
    std::string name;
    std::string purpose;                       // declared purpose, e.g. "notes"
    std::vector<PermissionRequest> permissions;

public:
    AppClient(const std::string& name, const std::string& purpose);

    const std::string& getName() const;
    const std::string& getPurpose() const;
    const std::vector<PermissionRequest>& getPermissions() const;

    void addPermission(const std::string& permissionName);   // throws if unknown
    bool removePermission(const std::string& permissionName);
    bool hasPermission(const std::string& permissionName) const;

    std::string serialize() const;                      // name|purpose|perm1,perm2
    static AppClient fromLine(const std::string& line); // throws if malformed

    static const std::vector<std::string>& validPurposes();
    static bool isValidPurpose(const std::string& purpose);
};

#endif
