#include "DataAsset.h"
#include <stdexcept>

DataAsset::DataAsset(const std::string& name, int sensitivity)
    : name(name), sensitivity(sensitivity) {}

const std::string& DataAsset::getName() const { return name; }
int DataAsset::getSensitivity() const { return sensitivity; }
bool DataAsset::isHighlySensitive() const { return sensitivity >= 7; }

const std::map<std::string, int>& DataAsset::catalogue() {
    static const std::map<std::string, int> table = {
        {"location", 8}, {"contacts", 7}, {"documents", 6}, {"camera", 7},
        {"microphone", 8}, {"sms", 9}, {"calendar", 4}, {"storage", 3},
        {"bluetooth", 5}, {"call_logs", 9}, {"notifications", 3},
        {"nearby_devices", 6}, {"biometrics", 10}, {"health_data", 10},
        {"network_state", 2}
    };
    return table;
}

bool DataAsset::isKnown(const std::string& name) {
    return catalogue().count(name) > 0;
}

DataAsset DataAsset::make(const std::string& name) {
    auto it = catalogue().find(name);
    if (it == catalogue().end())
        throw std::invalid_argument("Unknown permission: " + name);
    return DataAsset(it->first, it->second);
}
