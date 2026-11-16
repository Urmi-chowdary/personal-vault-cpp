#include "ReportGenerator.h"
#include <fstream>
#include <stdexcept>

std::string ReportGenerator::build(const AppClient& app, const std::vector<Finding>& findings,
                                   int score, const std::string& level,
                                   const std::vector<std::string>& removals) const {
    std::string r;
    r += "==============================================\n";
    r += " RISK REPORT: " + app.getName() + "  (purpose: " + app.getPurpose() + ")\n";
    r += "==============================================\n";
    r += "Permissions requested: ";
    if (app.getPermissions().empty()) r += "none";
    for (std::size_t i = 0; i < app.getPermissions().size(); ++i) {
        if (i) r += ", ";
        r += app.getPermissions()[i].getName();
    }
    r += "\n\nRisk score: " + std::to_string(score) + "/100  [" + level + "]\n\n";

    if (findings.empty()) {
        r += "No risks found. Permissions match the declared purpose.\n";
    } else {
        r += "Why this score:\n";
        for (const auto& f : findings)
            r += "  +" + std::to_string(f.points) + "  (" + f.rule + ") " + f.explanation + "\n";
    }

    r += "\nSafer configuration: ";
    if (removals.empty()) {
        r += "no changes needed.\n";
    } else {
        r += "remove ";
        for (std::size_t i = 0; i < removals.size(); ++i) {
            if (i) r += ", ";
            r += removals[i];
        }
        r += "\n";
    }
    return r;
}

void ReportGenerator::saveToFile(const std::string& text, const std::string& fileName) const {
    std::ofstream out(fileName);
    if (!out) throw std::runtime_error("Cannot write file: " + fileName);
    out << text;
}
