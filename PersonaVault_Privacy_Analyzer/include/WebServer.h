#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <map>
#include <string>
#include "SentinelService.h"
#include "WebsiteRiskScanner.h"

// A tiny HTTP server (plain POSIX sockets) that serves the web page and a JSON API.
class WebServer {
private:
    SentinelService& service;
    WebsiteRiskScanner websiteScanner;
    int port;
    std::string webDir;

    std::string handle(const std::string& method, const std::string& path,
                       const std::map<std::string, std::string>& params);
    static std::string respond(int status, const std::string& type, const std::string& body);
    static std::map<std::string, std::string> parseParams(const std::string& text);
    static std::string urlDecode(const std::string& s);
    std::string readFile(const std::string& name) const;

public:
    WebServer(SentinelService& service, int port, const std::string& webDir);
    void run();
};

#endif
