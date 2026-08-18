# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 4321_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4321_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 15-55 of the vulnerable file.

#endif

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
@@ -32,6 +32,8 @@
 #include "qtcompat_p.h"
 
 #define MIN_VERSION_WITH_SSL_SUPPORT 6
+
+static const int MAX_UNPAIRED_CONNECTIONS = 42;
 
 LanLinkProvider::LanLinkProvider(
         bool testMode,
@@ -580,6 +582,15 @@
         deviceLink->reset(socket, connectionOrigin);
     } else {
         deviceLink = new LanDeviceLink(deviceId, this, socket, connectionOrigin);
+        // Socket disconnection will now be handled by LanDeviceLink
+        disconnect(socket, &QAbstractSocket::disconnected, socket, &QObject::deleteLater);
+        bool isDeviceTrusted = KdeConnectConfig::instance().trustedDevices().contains(deviceId);
+        if (!isDeviceTrusted && m_links.size() > MAX_UNPAIRED_CONNECTIONS) {
+            qCWarning(KDECONNECT_CORE) << "Too many unpaired devices to remember them all. Ignoring " << deviceId;
+            socket->disconnectFromHost();
+            socket->deleteLater();
+            return;
+        }
         connect(deviceLink, &QObject::destroyed, this, &LanLinkProvider::deviceLinkDestroyed);
         m_links[deviceId] = deviceLink;
         if (m_pairingHandlers.contains(deviceId)) {
```
