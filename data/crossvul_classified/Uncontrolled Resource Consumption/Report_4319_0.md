# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 4319_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4319_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 375-415 of the vulnerable file.

        delete m_receivedIdentityPackets.take(socket).np;
    }
}

//I'm the new device and this is the answer to my UDP identity packet (no data received yet). They are connecting to us through TCP, and they should send an identity.
void LanLinkProvider::newConnection()
{
    qCDebug(KDECONNECT_CORE) << "LanLinkProvider newConnection";

    while (m_server->hasPendingConnections()) {
        QSslSocket* socket = m_server->nextPendingConnection();
        configureSocket(socket);
        //This socket is still managed by us (and child of the QTcpServer), if
        //it disconnects before we manage to pass it to a LanDeviceLink, it's
        //our responsibility to delete it. We do so with this connection.
        connect(socket, &QAbstractSocket::disconnected,
                socket, &QObject::deleteLater);
        connect(socket, &QIODevice::readyRead,
                this, &LanLinkProvider::dataReceived);

    }
}

//I'm the new device and this is the answer to my UDP identity packet (data received)
void LanLinkProvider::dataReceived()
{
    QSslSocket* socket = qobject_cast<QSslSocket*>(sender());
    //the size here is arbitrary and is now at 8192 bytes. It needs to be considerably long as it includes the capabilities but there needs to be a limit
    //Tested between my systems and I get around 2000 per identity package.
    if (socket->bytesAvailable() > 8192) {
        qCWarning(KDECONNECT_CORE) << "LanLinkProvider/newConnection: Suspiciously long identity package received. Closing connection." << socket->peerAddress() << socket->bytesAvailable();
        socket->disconnectFromHost();
        return;
    }

#if QT_VERSION < QT_VERSION_CHECK(5,7,0)
    if (!socket->canReadLine())
        return;
#else
    socket->startTransaction();
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -392,6 +392,16 @@
         connect(socket, &QIODevice::readyRead,
                 this, &LanLinkProvider::dataReceived);
 
+        QTimer* timer = new QTimer(socket);
+        timer->setSingleShot(true);
+        timer->setInterval(1000);
+        connect(socket, &QSslSocket::encrypted,
+                timer, &QObject::deleteLater);
+        connect(timer, &QTimer::timeout, socket, [socket] {
+            qCWarning(KDECONNECT_CORE) << "LanLinkProvider/newConnection: Host timed out without sending any identity." << socket->peerAddress();
+            socket->disconnectFromHost();
+        });
+        timer->start();
     }
 }
 
```
