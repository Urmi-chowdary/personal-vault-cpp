#ifndef DATAASSET_H
#define DATAASSET_H

#include <string>
#include <map>

// Describes one kind of personal data (e.g. "location") and how sensitive it is.
class DataAsset {
private:                       // ENCAPSULATION: fields hidden, read through getters
    std::string name;
    int sensitivity;           // 1 (low) .. 10 (very high)

public:
    DataAsset(const std::string& name, int sensitivity);

    const std::string& getName() const;
    int getSensitivity() const;
    bool isHighlySensitive() const;

    // Catalogue of every known permission and its sensitivity weight
    static const std::map<std::string, int>& catalogue();
    static bool isKnown(const std::string& name);
    static DataAsset make(const std::string& name);   // throws if unknown
};

#endif
