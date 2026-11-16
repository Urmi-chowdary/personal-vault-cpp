#include "RiskScorer.h"
#include <algorithm>

int RiskScorer::score(const std::vector<Finding>& findings) const {
    int total = 0;
    for (const auto& f : findings) total += f.points;
    return std::min(total, 100);
}

std::string RiskScorer::level(int s) const {
    if (s < 20) return "LOW";
    if (s < 45) return "MEDIUM";
    if (s < 70) return "HIGH";
    return "CRITICAL";
}

std::vector<std::string> RiskScorer::safeRemovals(const std::vector<Finding>& findings) const {
    std::vector<std::string> out;
    for (const auto& f : findings)
        for (const auto& p : f.removeSuggestion)
            if (std::find(out.begin(), out.end(), p) == out.end()) out.push_back(p);
    return out;
}
