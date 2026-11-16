#include "MenuInterface.h"
#include "Utils.h"
#include <cstdlib>
#include <iostream>
#include <stdexcept>

MenuInterface::MenuInterface() : audit("audit_log.txt"), consents(audit) {}

std::string MenuInterface::ask(const std::string& prompt) const {
    std::cout << prompt;
    std::string s;
    if (!std::getline(std::cin, s)) std::exit(0);
    return s;
}

int MenuInterface::askInt(const std::string& prompt) const {
    while (true) {
        try { return std::stoi(ask(prompt)); }
        catch (...) { std::cout << "Please enter a valid number.\n"; }
    }
}

AppClient* MenuInterface::findApp(const std::string& name) {
    for (auto& a : apps) if (a.getName() == name) return &a;
    return nullptr;
}

void MenuInterface::registerApp() {
    std::string name = ask("App name: ");
    if (name.empty()) throw std::invalid_argument("App name cannot be empty");
    if (findApp(name)) throw std::invalid_argument("App already registered");

    std::cout << "Purposes: ";
    for (const auto& p : AppClient::validPurposes()) std::cout << p << " ";
    std::cout << "\n";
    std::string purpose = ask("Declared purpose: ");
    if (!AppClient::isValidPurpose(purpose)) throw std::invalid_argument("Unknown purpose");

    AppClient app(name, purpose);
    std::cout << "Available permissions: ";
    for (const auto& kv : DataAsset::catalogue()) std::cout << kv.first << " ";
    std::cout << "\n";
    std::string line = ask("Requested permissions (comma separated): ");
    for (const auto& p : splitString(line, ','))
        if (!p.empty()) app.addPermission(p);      // throws if unknown

    apps.push_back(app);
    audit.record("APP REGISTERED: " + name + " (" + purpose + ")");
    std::cout << "App registered.\n";
}

void MenuInterface::listApps() const {
    if (apps.empty()) { std::cout << "No apps registered.\n"; return; }
    for (const auto& a : apps) std::cout << " - " << a.serialize() << "\n";
}

void MenuInterface::analyzeApp() {
    AppClient* app = findApp(ask("App name: "));
    if (!app) throw std::invalid_argument("App not found");
    std::vector<Finding> findings = engine.evaluate(*app);
    int s = scorer.score(findings);
    std::string lvl = scorer.level(s);
    std::string text = reporter.build(*app, findings, s, lvl, scorer.safeRemovals(findings));
    std::cout << text;
    reporter.saveToFile(text, "report_" + app->getName() + ".txt");
    audit.record("ANALYZED: " + app->getName() + " score " + std::to_string(s) + " " + lvl);
}

void MenuInterface::decidePermissions() {
    AppClient* app = findApp(ask("App name: "));
    if (!app) throw std::invalid_argument("App not found");
    for (const auto& p : app->getPermissions()) {
        std::string ans = ask("Allow '" + p.getName() + "' for " + app->getName() + "? (y/n): ");
        consents.decide(app->getName(), p.getName(), ans == "y" || ans == "Y");
    }
}

void MenuInterface::applySaferConfig() {
    AppClient* app = findApp(ask("App name: "));
    if (!app) throw std::invalid_argument("App not found");
    std::vector<std::string> removals = scorer.safeRemovals(engine.evaluate(*app));
    if (removals.empty()) { std::cout << "Already safe. Nothing to remove.\n"; return; }
    for (const auto& p : removals) {
        app->removePermission(p);
        consents.revoke(app->getName(), p);
        audit.record("SAFER CONFIG: removed " + p + " from " + app->getName());
    }
    std::cout << "Removed risky permissions. New risk score: "
              << scorer.score(engine.evaluate(*app)) << "/100\n";
}

void MenuInterface::revokeConsent() {
    std::string app = ask("App name: ");
    std::string perm = ask("Permission: ");
    std::cout << (consents.revoke(app, perm) ? "Consent revoked.\n"
                                             : "No active consent found.\n");
}

void MenuInterface::saveAll() {
    storage.saveApps(apps);
    storage.saveConsents(consents);
    audit.record("DATA SAVED");
    std::cout << "Saved apps and consents.\n";
}

void MenuInterface::loadAll() {
    apps = storage.loadApps();
    storage.loadConsents(consents);
    audit.record("DATA LOADED");
    std::cout << "Loaded " << apps.size() << " app(s).\n";
}

void MenuInterface::run() {
    int choice = -1;
    while (choice != 0) {
        std::cout << "\n===== PersonaVault Sentinel =====\n"
                  << " 1. Register app\n"
                  << " 2. List apps\n"
                  << " 3. Analyze app risk (report)\n"
                  << " 4. Grant / deny permissions\n"
                  << " 5. Apply safer configuration\n"
                  << " 6. Revoke consent\n"
                  << " 7. View consent history\n"
                  << " 8. View audit history\n"
                  << " 9. Save data\n"
                  << "10. Load data\n"
                  << " 0. Exit\n";
        choice = askInt("Enter choice: ");
        try {
            switch (choice) {
            case 1: registerApp(); break;
            case 2: listApps(); break;
            case 3: analyzeApp(); break;
            case 4: decidePermissions(); break;
            case 5: applySaferConfig(); break;
            case 6: revokeConsent(); break;
            case 7: consents.show(); break;
            case 8: audit.show(); break;
            case 9: saveAll(); break;
            case 10: loadAll(); break;
            case 0: std::cout << "Goodbye!\n"; break;
            default: std::cout << "Invalid choice.\n";
            }
        } catch (const std::exception& e) {
            std::cout << "Error: " << e.what() << "\n";
        }
    }
}
