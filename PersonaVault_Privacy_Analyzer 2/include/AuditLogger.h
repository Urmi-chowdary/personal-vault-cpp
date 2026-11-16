#ifndef AUDITLOGGER_H
#define AUDITLOGGER_H

#include <string>
#include <vector>

// Keeps a permanent history of every decision (saved to a text file).
class AuditLogger {
private:
    std::vector<std::string> entries;
    std::string fileName;

public:
    explicit AuditLogger(const std::string& fileName = "audit_log.txt");
    void record(const std::string& event);
    void show() const;
    const std::vector<std::string>& getEntries() const;
};

#endif
