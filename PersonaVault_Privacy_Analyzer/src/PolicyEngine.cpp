#include "PolicyEngine.h"
#include <utility>

PolicyEngine::PolicyEngine() {
    rules.push_back(std::unique_ptr<Rule>(new PurposeRule()));
    rules.push_back(std::unique_ptr<Rule>(new CombinationRule()));
    rules.push_back(std::unique_ptr<Rule>(new SensitivityRule()));
}

void PolicyEngine::addRule(std::unique_ptr<Rule> rule) {
    rules.push_back(std::move(rule));
}

std::size_t PolicyEngine::ruleCount() const { return rules.size(); }

std::vector<Finding> PolicyEngine::evaluate(const AppClient& app) const {
    std::vector<Finding> all;
    for (const auto& r : rules) {
        std::vector<Finding> found = r->evaluate(app);   // runtime polymorphism
        all.insert(all.end(), found.begin(), found.end());
    }
    return all;
}
