#include "WebServer.h"
#include "Utils.h"
#include <arpa/inet.h>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <unistd.h>

WebServer::WebServer(SentinelService& service, int port, const std::string& webDir)
    : service(service), port(port), webDir(webDir) {}

std::string WebServer::urlDecode(const std::string& s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '+') out += ' ';
        else if (s[i] == '%' && i + 2 < s.size() + 0 && std::isxdigit(s[i + 1]) && std::isxdigit(s[i + 2])) {
            out += static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16));
            i += 2;
        } else out += s[i];
    }
    return out;
}

std::map<std::string, std::string> WebServer::parseParams(const std::string& text) {
    std::map<std::string, std::string> p;
    for (const auto& pair : splitString(text, '&')) {
        std::size_t eq = pair.find('=');
        if (eq == std::string::npos) continue;
        p[urlDecode(pair.substr(0, eq))] = urlDecode(pair.substr(eq + 1));
    }
    return p;
}

std::string WebServer::respond(int status, const std::string& type, const std::string& body) {
    std::string text = status == 200 ? "OK" : (status == 404 ? "Not Found" : "Bad Request");
    return "HTTP/1.1 " + std::to_string(status) + " " + text + "\r\n" +
           "Content-Type: " + type + "\r\n" +
           "Content-Length: " + std::to_string(body.size()) + "\r\n" +
           "Connection: close\r\n\r\n" + body;
}

std::string WebServer::readFile(const std::string& name) const {
    std::ifstream in(webDir + "/" + name, std::ios::binary);
    if (!in) throw std::runtime_error("File not found: " + name);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string WebServer::handle(const std::string& method, const std::string& path,
                              const std::map<std::string, std::string>& p) {
    auto get = [&](const std::string& k) {
        auto it = p.find(k);
        return it == p.end() ? std::string() : it->second;
    };
    const std::string json = "application/json";
    try {
        if (method == "GET" && (path == "/" || path == "/index.html"))
            return respond(200, "text/html; charset=utf-8", readFile("index.html"));
        if (method == "POST" && path == "/api/analyze") {
            const std::string appName = get("name").empty() ? "Demo application" : get("name");
            const std::string purpose = get("purpose");
            if (!AppClient::isValidPurpose(purpose))
                throw std::invalid_argument("Please select a valid application purpose.");

            AppClient app(appName, purpose);
            std::vector<std::string> selected = splitString(get("permissions"), ',');
            if (selected.empty() || (selected.size() == 1 && selected[0].empty()))
                throw std::invalid_argument("Select at least one permission to analyse.");
            for (const auto& permission : selected) {
                if (!permission.empty()) app.addPermission(permission);
            }

            PolicyEngine policy;
            RiskScorer risk;
            std::vector<Finding> findings = policy.evaluate(app);
            int score = risk.score(findings);
            std::vector<std::string> removals = risk.safeRemovals(findings);

            std::string j = "{\"name\":\"" + jsonEscape(appName) +
                "\",\"purpose\":\"" + jsonEscape(purpose) +
                "\",\"score\":" + std::to_string(score) +
                ",\"level\":\"" + risk.level(score) + "\",\"permissions\":[";
            for (std::size_t i = 0; i < selected.size(); ++i)
                j += (i ? "," : "") + std::string("\"") + jsonEscape(selected[i]) + "\"";
            j += "],\"findings\":[";
            for (std::size_t i = 0; i < findings.size(); ++i) {
                if (i) j += ",";
                j += "{\"rule\":\"" + jsonEscape(findings[i].rule) +
                     "\",\"points\":" + std::to_string(findings[i].points) +
                     ",\"explanation\":\"" + jsonEscape(findings[i].explanation) + "\"}";
            }
            j += "],\"recommendations\":[";
            for (std::size_t i = 0; i < removals.size(); ++i)
                j += (i ? "," : "") + std::string("\"") + jsonEscape(removals[i]) + "\"";
            if (findings.empty())
                j += "],\"summary\":\"No configured rules flagged this permission set. This is not a guarantee of privacy or safety.\"}";
            else
                j += "],\"summary\":\"Review the findings and remove permissions that are not essential to the app's stated purpose.\"}";
            return respond(200, json, j);
        }
        if (method == "POST" && path == "/api/scan") {
            std::vector<std::string> perms = splitString(get("permissions"), ',');
            WebsiteReport r = websiteScanner.scan(get("url"), perms);
            std::string j = "{\"url\":\"" + jsonEscape(r.url) + "\",\"host\":\"" + jsonEscape(r.host) +
                "\",\"score\":" + std::to_string(r.score) + ",\"level\":\"" + r.level + "\",\"findings\":[";
            for (std::size_t i=0;i<r.findings.size();++i) {
                if (i) j += ",";
                j += "{\"category\":\"" + jsonEscape(r.findings[i].category) + "\",\"message\":\"" +
                     jsonEscape(r.findings[i].message) + "\",\"points\":" + std::to_string(r.findings[i].points) + "}";
            }
            j += "],\"permissions\":[";
            for (std::size_t i=0;i<r.permissions.size();++i) j += (i ? "," : "") + std::string("\"") + jsonEscape(r.permissions[i]) + "\"";
            return respond(200, json, j + "]}");
        }
        if (method == "GET" && path == "/api/meta")   return respond(200, json, service.metaJson());
        if (method == "GET" && path == "/api/apps")   return respond(200, json, service.appsJson());
        if (method == "GET" && path == "/api/report") return respond(200, json, service.reportJson(get("app")));
        if (method == "GET" && path == "/api/audit")  return respond(200, json, service.auditJson());

        if (method == "POST" && path == "/api/apps") {
            service.registerApp(get("name"), get("purpose"), splitString(get("permissions"), ','));
            return respond(200, json, "{\"ok\":true}");
        }
        if (method == "POST" && path == "/api/remove") {
            return respond(200, json, service.removeApp(get("app")) ? "{\"ok\":true}" : "{\"ok\":false}");
        }
        if (method == "POST" && path == "/api/consent") {
            service.decide(get("app"), get("permission"), get("granted") == "1");
            return respond(200, json, "{\"ok\":true}");
        }
        if (method == "POST" && path == "/api/revoke") {
            return respond(200, json, service.revoke(get("app"), get("permission")) ? "{\"ok\":true}" : "{\"ok\":false}");
        }
        if (method == "POST" && path == "/api/safer") {
            std::vector<std::string> removed = service.applySaferConfig(get("app"));
            std::string j = "{\"removed\":[";
            for (std::size_t i = 0; i < removed.size(); ++i) j += (i ? "," : "") + std::string("\"") + removed[i] + "\"";
            return respond(200, json, j + "]}");
        }
        if (method == "POST" && path == "/api/save") { service.save(); return respond(200, json, "{\"ok\":true}"); }
        if (method == "POST" && path == "/api/load") { service.load(); return respond(200, json, "{\"ok\":true}"); }

        return respond(404, json, "{\"error\":\"Not found\"}");
    } catch (const std::exception& e) {
        return respond(400, json, "{\"error\":\"" + jsonEscape(e.what()) + "\"}");
    }
}

void WebServer::run() {
    std::signal(SIGPIPE, SIG_IGN);
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) throw std::runtime_error("Cannot create socket");
    int yes = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);      // only this computer can connect
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
        throw std::runtime_error("Cannot bind to port " + std::to_string(port) + " (already in use?)");
    if (listen(server, 16) < 0) throw std::runtime_error("Cannot listen");

    std::cout << "PersonaVault Sentinel running at http://localhost:" << port << "\n"
              << "Press Ctrl+C to stop.\n";

    while (true) {
        int client = accept(server, nullptr, nullptr);
        if (client < 0) continue;

        std::string data;
        char buf[4096];
        std::size_t headerEnd = std::string::npos;
        while (headerEnd == std::string::npos) {
            ssize_t n = recv(client, buf, sizeof(buf), 0);
            if (n <= 0) break;
            data.append(buf, static_cast<std::size_t>(n));
            headerEnd = data.find("\r\n\r\n");
            if (data.size() > 1000000) break;
        }
        if (headerEnd == std::string::npos) { close(client); continue; }

        std::string headers = data.substr(0, headerEnd);
        std::size_t contentLength = 0;
        std::size_t cl = headers.find("Content-Length:");
        if (cl == std::string::npos) cl = headers.find("content-length:");
        if (cl != std::string::npos) contentLength = static_cast<std::size_t>(std::atoi(headers.c_str() + cl + 15));
        std::string body = data.substr(headerEnd + 4);
        while (body.size() < contentLength) {
            ssize_t n = recv(client, buf, sizeof(buf), 0);
            if (n <= 0) break;
            body.append(buf, static_cast<std::size_t>(n));
        }

        std::istringstream firstLine(headers.substr(0, headers.find("\r\n")));
        std::string method, target, version;
        firstLine >> method >> target >> version;
        std::string path = target, query;
        std::size_t q = target.find('?');
        if (q != std::string::npos) { path = target.substr(0, q); query = target.substr(q + 1); }

        std::map<std::string, std::string> params = parseParams(query);
        for (const auto& kv : parseParams(body)) params[kv.first] = kv.second;

        std::string response = handle(method, path, params);
        std::size_t sent = 0;
        while (sent < response.size()) {
            ssize_t n = send(client, response.data() + sent, response.size() - sent, 0);
            if (n <= 0) break;
            sent += static_cast<std::size_t>(n);
        }
        close(client);
    }
}
