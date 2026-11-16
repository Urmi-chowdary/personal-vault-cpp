#ifndef FILESTORAGE_H
#define FILESTORAGE_H

#include <string>
#include <vector>
#include "AppClient.h"
#include "ConsentManager.h"

// FILE HANDLING: saves and loads apps and consent decisions as text files.
class FileStorage {
private:
    std::string appsFile;
    std::string consentsFile;

public:
    explicit FileStorage(const std::string& appsFile = "apps.txt",
                         const std::string& consentsFile = "consents.txt");

    void saveApps(const std::vector<AppClient>& apps) const;
    std::vector<AppClient> loadApps() const;            // throws if file missing
    void saveConsents(const ConsentManager& cm) const;
    void loadConsents(ConsentManager& cm) const;        // throws if file missing
};

#endif
