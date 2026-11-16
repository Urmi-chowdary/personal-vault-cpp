// Simple test suite (no external library needed). Run with: make test
#include <cstdio>
#include <iostream>
#include <memory>
#include "AppClient.h"
#include "PolicyEngine.h"
#include "RiskScorer.h"
#include "ConsentManager.h"
#include "FileStorage.h"
#include "WebsiteRiskScanner.h"

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do { \
    if (cond) { ++passed; std::cout << "  PASS: " << msg << "\n"; } \
    else      { ++failed; std::cout << "  FAIL: " << msg << "\n"; } } while (0)

int main() {
    std::cout << "Running PersonaVault Sentinel tests\n";
    PolicyEngine engine;
    RiskScorer scorer;

    // 1. A safe app
    AppClient safe("MapPro", "navigation");
    safe.addPermission("location");
    auto f1 = engine.evaluate(safe);
    CHECK(f1.empty() && scorer.score(f1) == 0, "navigation app with only location is risk-free");

    // 2. Over-privileged note app
    AppClient notes("AI Notes", "notes");
    notes.addPermission("documents");
    notes.addPermission("contacts");
    notes.addPermission("location");
    auto f2 = engine.evaluate(notes);
    int s2 = scorer.score(f2);
    CHECK(s2 > 0, "over-privileged notes app gets a positive risk score");
    CHECK(scorer.level(s2) == "HIGH" || scorer.level(s2) == "CRITICAL", "notes app with contacts+location is HIGH or above");
    auto rem = scorer.safeRemovals(f2);
    CHECK(rem.size() >= 2, "safer configuration suggests removing permissions");

    // 3. Applying the safer configuration lowers the score
    for (const auto& p : rem) notes.removePermission(p);
    CHECK(scorer.score(engine.evaluate(notes)) < s2, "risk score drops after removing suggested permissions");

    // 4. Score is capped at 100
    AppClient greedy("Greedy", "game");
    for (const char* p : {"location","contacts","documents","camera","microphone","sms","calendar"})
        greedy.addPermission(p);
    CHECK(scorer.score(engine.evaluate(greedy)) == 100, "score is capped at 100");

    // 5. Unknown permission throws
    bool threw = false;
    try { AppClient x("X", "game"); x.addPermission("teleport"); }
    catch (const std::invalid_argument&) { threw = true; }
    CHECK(threw, "unknown permission throws invalid_argument");

    // 5b. Expanded permission catalogue and combination analysis
    AppClient health("Wellness Tracker", "fitness");
    health.addPermission("health_data");
    health.addPermission("location");
    auto healthFindings = engine.evaluate(health);
    CHECK(DataAsset::isKnown("biometrics") && DataAsset::isKnown("call_logs"),
          "expanded permission catalogue recognises sensitive permission types");
    CHECK(!healthFindings.empty(), "health data and location combination produces a privacy finding");

    AppClient finance("Secure Wallet", "finance");
    finance.addPermission("biometrics");
    finance.addPermission("documents");
    CHECK(scorer.score(engine.evaluate(finance)) > 0,
          "biometrics and document combination is evaluated by privacy rules");

    // 6. Serialize / parse round trip
    AppClient round = AppClient::fromLine(notes.serialize());
    CHECK(round.getName() == notes.getName() && round.getPermissions().size() == notes.getPermissions().size(),
          "app survives serialize -> fromLine");

    // 7. Consent latest-record-wins and revoke
    AuditLogger audit("test_audit_log.txt");
    ConsentManager cm(audit);
    cm.decide("AI Notes", "documents", true);
    CHECK(cm.isGranted("AI Notes", "documents"), "consent granted is recorded");
    CHECK(cm.revoke("AI Notes", "documents") && !cm.isGranted("AI Notes", "documents"), "consent can be revoked");
    CHECK(!cm.revoke("AI Notes", "documents"), "revoking twice reports nothing to revoke");

    // 8. File storage round trip
    FileStorage fs("test_apps.txt", "test_consents.txt");
    fs.saveApps({safe, notes});
    fs.saveConsents(cm);
    auto loadedApps = fs.loadApps();
    ConsentManager cm2(audit);
    fs.loadConsents(cm2);
    CHECK(loadedApps.size() == 2, "apps are saved and loaded from file");
    CHECK(cm2.all().size() == cm.all().size(), "consents are saved and loaded from file");

    // 9. Website URL scanner: independent URL reports and proportional scoring
    WebsiteRiskScanner urlScanner;
    auto cleanUrl = urlScanner.scan("https://example.com", {});
    auto onePermission = urlScanner.scan("https://example.com", {"camera"});
    auto insecureUrl = urlScanner.scan("http://example.org", {});
    CHECK(cleanUrl.score == 0, "ordinary HTTPS URL has no obvious URL flags");
    CHECK(onePermission.score == 0 && onePermission.permissions.empty(),
          "website URL scan ignores permission input and needs no permissions");
    CHECK(insecureUrl.score == 18 && insecureUrl.url != cleanUrl.url,
          "each scanned URL gets its own independent report");

    // 10. Polymorphism: engine can accept a new Rule type
    class StrictRule : public Rule {
    public:
        std::string name() const override { return "StrictRule"; }
        std::vector<Finding> evaluate(const AppClient&) const override {
            return { {"StrictRule", 5, "custom rule fired", {}} };
        }
    };
    PolicyEngine custom;
    std::size_t before = custom.ruleCount();
    custom.addRule(std::unique_ptr<Rule>(new StrictRule()));
    CHECK(custom.ruleCount() == before + 1 && scorer.score(custom.evaluate(safe)) == 5,
          "a new Rule subclass plugs into the engine (polymorphism)");

    std::remove("test_audit_log.txt");
    std::remove("test_apps.txt");
    std::remove("test_consents.txt");

    std::cout << "\n" << passed << " passed, " << failed << " failed\n";
    return failed == 0 ? 0 : 1;
}
