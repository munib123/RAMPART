# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in cpp
**Pair ID:** 3200_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3200_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```cpp
Lines 1-24 of the vulnerable file.

#include "logger.h"

#include <QDateTime>

Logger* Logger::m_instance = 0;

Logger::Logger()
    : lock(QReadWriteLock::Recursive)
    , msgCounter(0)
    , peerCounter(0)
{
}

Logger::~Logger() {}

Logger *Logger::instance()
{
    return m_instance;
}

void Logger::initInstance()
{
    if (!m_instance)
        m_instance = new Logger;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,7 @@
 #include "logger.h"
 
 #include <QDateTime>
+#include "base/utils/string.h"
 
 Logger* Logger::m_instance = 0;
 
@@ -36,7 +37,7 @@
 {
     QWriteLocker locker(&lock);
 
-    Log::Msg temp = { msgCounter++, QDateTime::currentMSecsSinceEpoch(), type, message };
+    Log::Msg temp = { msgCounter++, QDateTime::currentMSecsSinceEpoch(), type, Utils::String::toHtmlEscaped(message) };
     m_messages.push_back(temp);
 
     if (m_messages.size() >= MAX_LOG_MESSAGES)
@@ -49,7 +50,7 @@
 {
     QWriteLocker locker(&lock);
 
-    Log::Peer temp = { peerCounter++, QDateTime::currentMSecsSinceEpoch(), ip, blocked, reason };
+    Log::Peer temp = { peerCounter++, QDateTime::currentMSecsSinceEpoch(), Utils::String::toHtmlEscaped(ip), blocked, Utils::String::toHtmlEscaped(reason) };
     m_peers.push_back(temp);
 
     if (m_peers.size() >= MAX_LOG_MESSAGES)
```
