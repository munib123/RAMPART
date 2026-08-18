# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3201_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3201_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 26-66 of the vulnerable file.

 * exception statement from your version.
 */

#ifndef HTTP_TYPES_H
#define HTTP_TYPES_H

#include <QString>
#include <QMap>
#include <QHostAddress>
#include <QVector>

#include "base/types.h"

namespace Http
{
    const QString HEADER_SET_COOKIE = "Set-Cookie";
    const QString HEADER_CONTENT_TYPE = "Content-Type";
    const QString HEADER_CONTENT_ENCODING = "Content-Encoding";
    const QString HEADER_CONTENT_LENGTH = "Content-Length";
    const QString HEADER_CACHE_CONTROL = "Cache-Control";

    const QString CONTENT_TYPE_CSS = "text/css; charset=UTF-8";
    const QString CONTENT_TYPE_GIF = "image/gif";
    const QString CONTENT_TYPE_HTML = "text/html; charset=UTF-8";
    const QString CONTENT_TYPE_JS = "application/javascript; charset=UTF-8";
    const QString CONTENT_TYPE_JSON = "application/json";
    const QString CONTENT_TYPE_PNG = "image/png";
    const QString CONTENT_TYPE_TXT = "text/plain; charset=UTF-8";

    struct Environment
    {
        QHostAddress clientAddress;
    };

    struct UploadedFile
    {
        QString filename; // original filename
        QString type; // MIME type
        QByteArray data; // File data
    };

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,6 +43,7 @@
     const QString HEADER_CONTENT_ENCODING = "Content-Encoding";
     const QString HEADER_CONTENT_LENGTH = "Content-Length";
     const QString HEADER_CACHE_CONTROL = "Cache-Control";
+    const QString HEADER_X_FRAME_OPTIONS = "X-Frame-Options";
 
     const QString CONTENT_TYPE_CSS = "text/css; charset=UTF-8";
     const QString CONTENT_TYPE_GIF = "image/gif";
```
