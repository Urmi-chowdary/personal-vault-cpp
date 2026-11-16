#include "AuditLogger.h"
#include "Utils.h"
#include <fstream>
#include <iostream>

AuditLogger::AuditLogger(const std::string& fileName) : fileName(fileName) {
    std::ifstream in(fileName);
    std::string line;
    while (std::getline(in, line))
        if (!line.empty()) entries.push_back(line);
}

void AuditLogger::record(const std::string& event) {
    std::string line = "[" + formatTime(std::time(nullptr)) + "] " + event;
    entries.push_back(line);
    std::ofstream out(fileName, std::ios::app);
    if (out) out << line << "\n";
}

void AuditLogger::show() const {
    if (entries.empty()) { std::cout << "No audit entries yet.\n"; return; }
    for (std::size_t i = 0; i < entries.size(); ++i)
        std::cout << (i + 1) << ". " << entries[i] << "\n";
}

const std::vector<std::string>& AuditLogger::getEntries() const { return entries; }
