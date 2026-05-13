#ifndef ATTACKANALYZER_H
#define ATTACKANALYZER_H

#include "LogList.h"

#include <string>
#include <vector>

class AttackAnalyzer {
public:
    static std::vector<std::string> findPortScans(const std::vector<LogRecord>& records, int portThreshold);
    static std::vector<std::string> findSuspiciousActivity(const std::vector<LogRecord>& records, int requestThreshold);
};

#endif
