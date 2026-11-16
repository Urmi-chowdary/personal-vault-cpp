#ifndef RULE_H
#define RULE_H

#include <string>
#include <vector>
#include "AppClient.h"

// One problem found by a rule, with a plain-language explanation.
struct Finding {
    std::string rule;
    int points;                                  // risk contribution
    std::string explanation;                     // WHY it is risky
    std::vector<std::string> removeSuggestion;   // permissions to drop
};

// ABSTRACTION: Rule defines WHAT a rule does, not HOW. Cannot be instantiated.
class Rule {
public:
    virtual ~Rule() {}
    virtual std::string name() const = 0;
    virtual std::vector<Finding> evaluate(const AppClient& app) const = 0;
};

// INHERITANCE: each concrete rule extends Rule
// Flags permissions that do not match the app's declared purpose.
class PurposeRule : public Rule {
public:
    std::string name() const override;
    std::vector<Finding> evaluate(const AppClient& app) const override;
    static const std::vector<std::string>& expectedFor(const std::string& purpose);
};

// Flags dangerous COMBINATIONS of permissions.
class CombinationRule : public Rule {
public:
    std::string name() const override;
    std::vector<Finding> evaluate(const AppClient& app) const override;
};

// Flags apps that collect too many highly sensitive permissions.
class SensitivityRule : public Rule {
public:
    std::string name() const override;
    std::vector<Finding> evaluate(const AppClient& app) const override;
};

#endif
