#ifndef WEBSITE_RISK_SCANNER_H
#define WEBSITE_RISK_SCANNER_H
#include <string>
#include <vector>

struct WebsiteFinding {
    std::string category;
    std::string message;
    int points;
};
struct WebsiteReport {
    std::string url;
    std::string host;
    int score;
    std::string level;
    std::vector<WebsiteFinding> findings;
    std::vector<std::string> permissions;
};

// OOP service: validates and evaluates website URL indicators only; no browser permissions are requested.
class WebsiteRiskScanner {
public:
    WebsiteReport scan(const std::string& input,
                       const std::vector<std::string>& observedPermissions = {}) const;
private:
    static std::string lower(std::string value);
    static bool contains(const std::string& text, const std::string& part);
    static std::string riskLevel(int score);
};
#endif
