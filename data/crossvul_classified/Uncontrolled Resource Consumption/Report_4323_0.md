# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 4323_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4323_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 7-39 of the vulnerable file.


#include "socketlinereader.h"

SocketLineReader::SocketLineReader(QSslSocket* socket, QObject* parent)
    : QObject(parent)
    , m_socket(socket)
{
    connect(m_socket, &QIODevice::readyRead,
            this, &SocketLineReader::dataReceived);
}

void SocketLineReader::dataReceived()
{
    while (m_socket->canReadLine()) {
        const QByteArray line = m_socket->readLine();
        if (line.length() > 1) { //we don't want a single \n
            m_packets.enqueue(line);
        }
    }

    //If we still have things to read from the socket, call dataReceived again
    //We do this manually because we do not trust readyRead to be emitted again
    //So we call this method again just in case.
    if (m_socket->bytesAvailable() > 0) {
        QMetaObject::invokeMethod(this, "dataReceived", Qt::QueuedConnection);
        return;
    }

    //If we have any packets, tell it to the world.
    if (!m_packets.isEmpty()) {
        Q_EMIT readyRead();
    }
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,14 +24,6 @@
         }
     }
 
-    //If we still have things to read from the socket, call dataReceived again
-    //We do this manually because we do not trust readyRead to be emitted again
-    //So we call this method again just in case.
-    if (m_socket->bytesAvailable() > 0) {
-        QMetaObject::invokeMethod(this, "dataReceived", Qt::QueuedConnection);
-        return;
-    }
-
     //If we have any packets, tell it to the world.
     if (!m_packets.isEmpty()) {
         Q_EMIT readyRead();
```
