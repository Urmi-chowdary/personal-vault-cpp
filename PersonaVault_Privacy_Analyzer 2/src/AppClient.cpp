#include "AppClient.h"
#include "Utils.h"
#include <algorithm>
#include <stdexcept>

AppClient::AppClient(const std::string& name, const std::string& purpose)
    : name(name), purpose(purpose) {}

const std::string& AppClient::getName() const { return name; }
const std::string& AppClient::getPurpose() const { return purpose; }
const std::vector<PermissionRequest>& AppClient::getPermissions() const { return permissions; }

void AppClient::addPermission(const std::string& permissionName) {
    if (hasPermission(permissionName)) return;   // ignore duplicates
    permissions.push_back(PermissionRequest(DataAsset::make(permissionName)));
}

bool AppClient::removePermission(const std::string& permissionName) {
    auto it = std::find_if(permissions.begin(), permissions.end(),
        [&](const PermissionRequest& p) { return p.getName() == permissionName; });
    if (it == permissions.end()) return false;
    permissions.erase(it);
    return true;
}

bool AppClient::hasPermission(const std::string& permissionName) const {
    for (const auto& p : permissions)
        if (p.getName() == permissionName) return true;
    return false;
}

std::string AppClient::serialize() const {
    std::string perms;
    for (std::size_t i = 0; i < permissions.size(); ++i) {
        if (i) perms += ",";
        perms += permissions[i].getName();
    }
    return name + "|" + purpose + "|" + perms;
}

AppClient AppClient::fromLine(const std::string& line) {
    std::vector<std::string> parts = splitString(line, '|');
    if (parts.size() < 2) throw std::invalid_argument("Malformed app line: " + line);
    AppClient app(parts[0], parts[1]);
    if (parts.size() >= 3) {
        for (const auto& perm : splitString(parts[2], ','))
            if (!perm.empty()) app.addPermission(perm);
    }
    return app;
}

const std::vector<std::string>& AppClient::validPurposes() {
    static const std::vector<std::string> list =
        {"notes", "navigation", "messaging", "camera", "game", "finance",
         "education", "fitness", "weather", "shopping"};
    return list;
}

bool AppClient::isValidPurpose(const std::string& purpose) {
    const auto& v = validPurposes();
    return std::find(v.begin(), v.end(), purpose) != v.end();
}
