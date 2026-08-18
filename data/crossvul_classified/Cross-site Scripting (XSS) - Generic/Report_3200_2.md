# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in c
**Pair ID:** 3200_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3200_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```c
Lines 30-55 of the vulnerable file.

#ifndef UTILS_STRING_H
#define UTILS_STRING_H

#include <string>

class QByteArray;
class QString;

namespace Utils
{
    namespace String
    {
        QString fromStdString(const std::string &str);
        std::string toStdString(const QString &str);
        QString fromDouble(double n, int precision);

        // Implements constant-time comparison to protect against timing attacks
        // Taken from https://crackstation.net/hashing-security.htm
        bool slowEquals(const QByteArray &a, const QByteArray &b);

        bool naturalCompareCaseSensitive(const QString &left, const QString &right);
        bool naturalCompareCaseInsensitive(const QString &left, const QString &right);
    }
}

#endif // UTILS_STRING_H
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,6 +47,8 @@
         // Taken from https://crackstation.net/hashing-security.htm
         bool slowEquals(const QByteArray &a, const QByteArray &b);
 
+        QString toHtmlEscaped(const QString &str);
+
         bool naturalCompareCaseSensitive(const QString &left, const QString &right);
         bool naturalCompareCaseInsensitive(const QString &left, const QString &right);
     }
```
