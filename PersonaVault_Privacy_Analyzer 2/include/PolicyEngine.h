#ifndef POLICYENGINE_H
#define POLICYENGINE_H

#include <memory>
#include <vector>
#include "Rule.h"

// Runs every rule against an app. POLYMORPHISM: it only knows the Rule base type.
class PolicyEngine {
private:
    std::vector<std::unique_ptr<Rule>> rules;

public:
    PolicyEngine();                          // installs the default rules
    void addRule(std::unique_ptr<Rule> rule);
    std::size_t ruleCount() const;
    std::vector<Finding> evaluate(const AppClient& app) const;
};

#endif
