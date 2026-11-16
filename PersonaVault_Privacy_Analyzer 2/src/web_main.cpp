#include <cstdlib>
#include <iostream>
#include "WebServer.h"

int main(int argc, char* argv[]) {
    int port = argc > 1 ? std::atoi(argv[1]) : 8080;
    try {
        SentinelService service;
        WebServer server(service, port, "web");
        server.run();
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
