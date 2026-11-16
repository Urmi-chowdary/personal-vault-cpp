#ifndef REPORTGENERATOR_H
#define REPORTGENERATOR_H

#include <string>
#include <vector>
#include "AppClient.h"
#include "Rule.h"

// Builds a human-readable, explainable risk report.
class ReportGenerator {
public:
    std::string build(const AppClient& app, const std::vector<Finding>& findings,
                      int score, const std::string& level,
                      const std::vector<std::string>& removals) const;
    void saveToFile(const std::string& text, const std::string& fileName) const;
};

#endif
