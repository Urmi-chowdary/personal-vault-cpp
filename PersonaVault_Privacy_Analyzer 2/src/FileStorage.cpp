#include "FileStorage.h"
#include "Utils.h"
#include <fstream>
#include <stdexcept>

FileStorage::FileStorage(const std::string& appsFile, const std::string& consentsFile)
    : appsFile(appsFile), consentsFile(consentsFile) {}

void FileStorage::saveApps(const std::vector<AppClient>& apps) const {
    std::ofstream out(appsFile);
    if (!out) throw std::runtime_error("Cannot write file: " + appsFile);
    for (const auto& a : apps) out << a.serialize() << "\n";
}

std::vector<AppClient> FileStorage::loadApps() const {
    std::ifstream in(appsFile);
    if (!in) throw std::runtime_error("No saved apps found (" + appsFile + ")");
    std::vector<AppClient> apps;
    std::string line;
    while (std::getline(in, line))
        if (!line.empty()) apps.push_back(AppClient::fromLine(line));
    return apps;
}

void FileStorage::saveConsents(const ConsentManager& cm) const {
    std::ofstream out(consentsFile);
    if (!out) throw std::runtime_error("Cannot write file: " + consentsFile);
    for (const auto& r : cm.all())
        out << r.app << "|" << r.permission << "|" << (r.granted ? 1 : 0)
            << "|" << static_cast<long long>(r.when) << "\n";
}

void FileStorage::loadConsents(ConsentManager& cm) const {
    std::ifstream in(consentsFile);
    if (!in) throw std::runtime_error("No saved consents found (" + consentsFile + ")");
    cm.clear();
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::vector<std::string> p = splitString(line, '|');
        if (p.size() != 4) throw std::runtime_error("Malformed consent line: " + line);
        cm.addLoaded({p[0], p[1], p[2] == "1", static_cast<std::time_t>(std::stoll(p[3]))});
    }
}
