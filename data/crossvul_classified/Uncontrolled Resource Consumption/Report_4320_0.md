# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 4320_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4320_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 382-422 of the vulnerable file.

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
#if QT_VERSION < QT_VERSION_CHECK(5,7,0)
    if (!socket->canReadLine())
        return;
#else
    socket->startTransaction();
#endif

    const QByteArray data = socket->readLine();

    qCDebug(KDECONNECT_CORE) << "LanLinkProvider received reply:" << data;

    NetworkPacket* np = new NetworkPacket(QLatin1String(""));
    bool success = NetworkPacket::unserialize(data, np);

#if QT_VERSION < QT_VERSION_CHECK(5,7,0)
    if (!success) {
        delete np;
        return;
    }
#else
    if (!success) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -399,6 +399,14 @@
 void LanLinkProvider::dataReceived()
 {
     QSslSocket* socket = qobject_cast<QSslSocket*>(sender());
+    //the size here is arbitrary and is now at 8192 bytes. It needs to be considerably long as it includes the capabilities but there needs to be a limit
+    //Tested between my systems and I get around 2000 per identity package.
+    if (socket->bytesAvailable() > 8192) {
+        qCWarning(KDECONNECT_CORE) << "LanLinkProvider/newConnection: Suspiciously long identity package received. Closing connection." << socket->peerAddress() << socket->bytesAvailable();
+        socket->disconnectFromHost();
+        return;
+    }
+
 #if QT_VERSION < QT_VERSION_CHECK(5,7,0)
     if (!socket->canReadLine())
         return;
```
