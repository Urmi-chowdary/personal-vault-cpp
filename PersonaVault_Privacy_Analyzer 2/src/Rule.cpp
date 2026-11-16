#include "Rule.h"
#include <algorithm>
#include <map>

// ---------- PurposeRule ----------
std::string PurposeRule::name() const { return "PurposeRule"; }

const std::vector<std::string>& PurposeRule::expectedFor(const std::string& purpose) {
    static const std::map<std::string, std::vector<std::string>> table = {
        {"notes",      {"documents", "storage", "notifications"}},
        {"navigation", {"location", "nearby_devices", "bluetooth", "network_state"}},
        {"messaging",  {"contacts", "camera", "microphone", "storage", "sms", "notifications", "call_logs"}},
        {"camera",     {"camera", "storage", "microphone"}},
        {"game",       {"storage", "notifications", "network_state", "nearby_devices"}},
        {"finance",    {"camera", "sms", "biometrics", "notifications", "network_state"}},
        {"education",  {"documents", "storage", "camera", "notifications"}},
        {"fitness",    {"location", "calendar", "health_data", "bluetooth"}},
        {"weather",    {"location", "notifications", "network_state"}},
        {"shopping",   {"storage", "camera", "notifications"}}
    };
    static const std::vector<std::string> none;
    auto it = table.find(purpose);
    return it == table.end() ? none : it->second;
}

std::vector<Finding> PurposeRule::evaluate(const AppClient& app) const {
    std::vector<Finding> out;
    const auto& expected = expectedFor(app.getPurpose());
    for (const auto& p : app.getPermissions()) {
        bool ok = std::find(expected.begin(), expected.end(), p.getName()) != expected.end();
        if (!ok) {
            out.push_back({name(), p.getSensitivity() * 3,
                "'" + p.getName() + "' is not needed for a '" + app.getPurpose() + "' app",
                {p.getName()}});
        }
    }
    return out;
}

// ---------- CombinationRule ----------
std::string CombinationRule::name() const { return "CombinationRule"; }

std::vector<Finding> CombinationRule::evaluate(const AppClient& app) const {
    struct Combo { const char* a; const char* b; int points; const char* why; };
    static const Combo combos[] = {
        {"contacts", "location", 15, "together they reveal who you know and where you are"},
        {"call_logs", "contacts", 18, "together they can expose communication networks and call patterns"},
        {"health_data", "location", 18, "together they can connect sensitive health details with movement patterns"},
        {"biometrics", "documents", 16, "together they combine identity signals with personal files"},
        {"nearby_devices", "location", 12, "together they can help infer a user's physical surroundings"},
        {"bluetooth", "nearby_devices", 8, "together they expand access to nearby connected devices"},
        {"microphone", "location", 15, "together they can record conversations at known places"},
        {"camera", "microphone", 10, "together they allow full audio-video surveillance"},
        {"documents", "contacts", 12, "together they let private files be tied to real people"},
        {"sms", "contacts", 12, "together they enable impersonation and message harvesting"}
    };
    std::vector<Finding> out;
    for (const auto& c : combos) {
        if (app.hasPermission(c.a) && app.hasPermission(c.b)) {
            out.push_back({name(), c.points,
                std::string("Risky combination '") + c.a + " + " + c.b + "': " + c.why,
                {c.b}});
        }
    }
    return out;
}

// ---------- SensitivityRule ----------
std::string SensitivityRule::name() const { return "SensitivityRule"; }

std::vector<Finding> SensitivityRule::evaluate(const AppClient& app) const {
    int high = 0;
    for (const auto& p : app.getPermissions())
        if (p.isHighlySensitive()) ++high;

    std::vector<Finding> out;
    if (high >= 3) {
        out.push_back({name(), (high - 2) * 10,
            "App requests " + std::to_string(high) + " highly sensitive permissions",
            {}});
    }
    return out;
}
