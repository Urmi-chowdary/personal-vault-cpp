#ifndef RISKSCORER_H
#define RISKSCORER_H

#include <string>
#include <vector>
#include "Rule.h"

// Turns findings into an explainable 0-100 risk score and a safer configuration.
class RiskScorer {
public:
    int score(const std::vector<Finding>& findings) const;          // capped at 100
    std::string level(int score) const;                              // LOW..CRITICAL
    std::vector<std::string> safeRemovals(const std::vector<Finding>& findings) const;
};

#endif
