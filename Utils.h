#ifndef UTILS_H
#define UTILS_H

#include <ctime>
#include <string>
#include <vector>
#include <sstream>

inline std::string formatTime(std::time_t t) {
    char buf[32];
    std::tm* tmv = std::localtime(&t);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tmv);
    return std::string(buf);
}

inline std::vector<std::string> splitString(const std::string& s, char sep) {
    std::vector<std::string> parts;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, sep)) parts.push_back(item);
    return parts;
}

// Escapes text so it can sit safely inside a JSON string
inline std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out += c;
        }
    }
    return out;
}

#endif
