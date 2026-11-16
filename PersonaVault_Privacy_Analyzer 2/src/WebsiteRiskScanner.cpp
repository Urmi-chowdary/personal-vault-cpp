#include "WebsiteRiskScanner.h"
#include <algorithm>
#include <cctype>
#include <stdexcept>

std::string WebsiteRiskScanner::lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}
bool WebsiteRiskScanner::contains(const std::string& s, const std::string& p) { return s.find(p) != std::string::npos; }
std::string WebsiteRiskScanner::riskLevel(int s) {
    if (s < 20) return "LOW";
    if (s < 40) return "GUARDED";
    if (s < 65) return "HIGH";
    return "CRITICAL";
}
WebsiteReport WebsiteRiskScanner::scan(const std::string& input, const std::vector<std::string>& observed) const {
    (void)observed; // retained in the interface for compatibility; permission data is not used.
    std::string url = input;
    if (url.empty()) throw std::invalid_argument("Paste a website URL first.");
    if (url.find(' ') != std::string::npos) throw std::invalid_argument("URL cannot contain spaces.");
    if (url.find("http://") != 0 && url.find("https://") != 0) url = "https://" + url;
    std::string scheme = url.substr(0, url.find("://"));
    std::string rest = url.substr(url.find("://") + 3);
    std::size_t end = rest.find_first_of("/?#:");
    std::string host = lower(rest.substr(0, end));
    if (host.empty() || host.find('.') == std::string::npos || host.front()=='.' || host.back()=='.')
        throw std::invalid_argument("Enter a valid website address, such as https://example.com.");
    if (host.find('@') != std::string::npos) throw std::invalid_argument("Invalid host section in URL.");

    WebsiteReport r; r.url=url; r.host=host; r.score=0; r.permissions.clear();
    auto add = [&](const std::string& c, const std::string& m, int pts) { r.findings.push_back({c,m,pts}); r.score += pts; };
    if (scheme == "http") add("Connection security", "This link uses HTTP, so the connection is not protected by HTTPS.", 18);
    if (host.size() > 55) add("Unusual domain", "The domain name is unusually long. Check it carefully for imitation or extra words.", 10);
    if (std::count(host.begin(), host.end(), '-') >= 3) add("Unusual domain", "The domain contains several hyphens, which can be used in look-alike addresses.", 9);
    if (std::count(host.begin(), host.end(), '.') >= 4) add("Unusual domain", "The address contains many subdomain levels. Verify the actual registered domain.", 8);
    bool numeric = !host.empty() && std::all_of(host.begin(), host.end(), [](unsigned char c){ return std::isdigit(c) || c=='.'; });
    if (numeric) add("IP-based address", "The link uses a numeric IP address instead of a recognisable domain.", 18);
    const std::vector<std::string> bait = {"login", "verify", "account", "secure", "update", "free", "gift", "claim", "reward", "wallet", "bank", "payment", "urgent"};
    int baitCount=0; for (const auto& w : bait) if (contains(lower(url), w)) ++baitCount;
    if (baitCount >= 2) add("Pressure / bait words", "Multiple login, payment, reward or urgency-related words appear in the URL. This is a warning sign, not proof of fraud.", std::min(18, 7 + baitCount*2));
    if (contains(host, "xn--")) add("Internationalised domain", "The domain uses punycode. Check for look-alike characters before trusting it.", 14);
    if (contains(url, "@")) add("URL disguise", "An @ symbol appears in the URL and may make the destination confusing.", 16);
    if (contains(url, "%")) add("Encoded characters", "The URL contains encoded characters. Inspect the destination carefully.", 5);
    if (contains(url, "//") && url.find("://") != url.find_last_of("//")) { /* protocol separators are normal; no score */ }

    // Permission analysis is intentionally excluded: this version evaluates the URL only.
    r.score = std::min(100, r.score);
    r.level = riskLevel(r.score);
    if (r.findings.empty()) r.findings.push_back({"No obvious URL flags", "No common suspicious URL indicators were detected by this basic checker. This does not prove the website is safe.", 0});
    return r;
}
