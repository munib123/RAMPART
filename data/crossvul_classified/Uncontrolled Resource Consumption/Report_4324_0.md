# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 4324_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4324_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 224-264 of the vulnerable file.


        if (!success) {
            qCDebug(KDECONNECT_CORE) << "Could not unserialize UDP packet";
            delete receivedPacket;
            continue;
        }

        if (receivedPacket->type() != PACKET_TYPE_IDENTITY) {
            qCDebug(KDECONNECT_CORE) << "Received a UDP packet of wrong type" << receivedPacket->type();
            delete receivedPacket;
            continue;
        }

        if (receivedPacket->get<QString>(QStringLiteral("deviceId")) == KdeConnectConfig::instance().deviceId()) {
            //qCDebug(KDECONNECT_CORE) << "Ignoring my own broadcast";
            delete receivedPacket;
            continue;
        }

        int tcpPort = receivedPacket->get<int>(QStringLiteral("tcpPort"));

        //qCDebug(KDECONNECT_CORE) << "Received Udp identity packet from" << sender << " asking for a tcp connection on port " << tcpPort;

        if (m_receivedIdentityPackets.size() > MAX_REMEMBERED_IDENTITY_PACKETS) {
            qCWarning(KDECONNECT_CORE) << "Too many remembered identities, ignoring" << receivedPacket->get<QString>(QStringLiteral("deviceId")) << "received via UDP";
            delete receivedPacket;
            continue;
        }

        QSslSocket* socket = new QSslSocket(this);
        socket->setProxy(QNetworkProxy::NoProxy);
        m_receivedIdentityPackets[socket].np = receivedPacket;
        m_receivedIdentityPackets[socket].sender = sender;
        connect(socket, &QAbstractSocket::connected, this, &LanLinkProvider::tcpSocketConnected);
#if QT_VERSION < QT_VERSION_CHECK(5,15,0)
        connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::error), this, &LanLinkProvider::connectError);
#else
        connect(socket, &QAbstractSocket::errorOccurred, this, &LanLinkProvider::connectError);
#endif
        socket->connectToHost(sender, tcpPort);
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -241,6 +241,11 @@
         }
 
         int tcpPort = receivedPacket->get<int>(QStringLiteral("tcpPort"));
+        if (tcpPort < MIN_TCP_PORT || tcpPort > MAX_TCP_PORT) {
+            qCDebug(KDECONNECT_CORE) << "TCP port outside of kdeconnect's range";
+            delete receivedPacket;
+            continue;
+        }
 
         //qCDebug(KDECONNECT_CORE) << "Received Udp identity packet from" << sender << " asking for a tcp connection on port " << tcpPort;
 
```
