# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 4322_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4322_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 17-57 of the vulnerable file.

#include <QHostInfo>
#include <QTcpServer>
#include <QMetaEnum>
#include <QNetworkProxy>
#include <QUdpSocket>
#include <QNetworkSession>
#include <QNetworkConfigurationManager>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslKey>

#include "daemon.h"
#include "landevicelink.h"
#include "lanpairinghandler.h"
#include "kdeconnectconfig.h"
#include "qtcompat_p.h"

#define MIN_VERSION_WITH_SSL_SUPPORT 6

static const int MAX_UNPAIRED_CONNECTIONS = 42;

LanLinkProvider::LanLinkProvider(
        bool testMode,
        quint16 udpBroadcastPort,
        quint16 udpListenPort
        )
    : m_server(new Server(this))
    , m_udpSocket(this)
    , m_tcpPort(0)
    , m_udpBroadcastPort(udpBroadcastPort)
    , m_udpListenPort(udpListenPort)
    , m_testMode(testMode)
    , m_combineBroadcastsTimer(this)
{

    m_combineBroadcastsTimer.setInterval(0); // increase this if waiting a single event-loop iteration is not enough
    m_combineBroadcastsTimer.setSingleShot(true);
    connect(&m_combineBroadcastsTimer, &QTimer::timeout, this, &LanLinkProvider::broadcastToNetwork);

    connect(&m_udpSocket, &QIODevice::readyRead, this, &LanLinkProvider::udpBroadcastReceived);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -34,6 +34,7 @@
 #define MIN_VERSION_WITH_SSL_SUPPORT 6
 
 static const int MAX_UNPAIRED_CONNECTIONS = 42;
+static const int MAX_REMEMBERED_IDENTITY_PACKETS = 42;
 
 LanLinkProvider::LanLinkProvider(
         bool testMode,
@@ -243,6 +244,12 @@
 
         //qCDebug(KDECONNECT_CORE) << "Received Udp identity packet from" << sender << " asking for a tcp connection on port " << tcpPort;
 
+        if (m_receivedIdentityPackets.size() > MAX_REMEMBERED_IDENTITY_PACKETS) {
+            qCWarning(KDECONNECT_CORE) << "Too many remembered identities, ignoring" << receivedPacket->get<QString>(QStringLiteral("deviceId")) << "received via UDP";
+            delete receivedPacket;
+            continue;
+        }
+
         QSslSocket* socket = new QSslSocket(this);
         socket->setProxy(QNetworkProxy::NoProxy);
         m_receivedIdentityPackets[socket].np = receivedPacket;
@@ -449,6 +456,12 @@
 
     if (np->type() != PACKET_TYPE_IDENTITY) {
         qCWarning(KDECONNECT_CORE) << "LanLinkProvider/newConnection: Expected identity, received " << np->type();
+        delete np;
+        return;
+    }
+
+    if (m_receivedIdentityPackets.size() > MAX_REMEMBERED_IDENTITY_PACKETS) {
+        qCWarning(KDECONNECT_CORE) << "Too many remembered identities, ignoring" << np->get<QString>(QStringLiteral("deviceId")) << "received via TCP";
         delete np;
         return;
     }
```
