# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1539_3
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1539_3`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 22-62 of the vulnerable file.

#define CORENETWORK_H

#include "network.h"
#include "coreircchannel.h"
#include "coreircuser.h"

#include <QTimer>

#ifdef HAVE_SSL
# include <QSslSocket>
# include <QSslError>
#else
# include <QTcpSocket>
#endif

#ifdef HAVE_QCA2
#  include "cipher.h"
#endif

#include "coresession.h"

class CoreIdentity;
class CoreUserInputHandler;
class CoreIgnoreListManager;
class Event;

class CoreNetwork : public Network
{
    SYNCABLE_OBJECT
        Q_OBJECT

public:
    CoreNetwork(const NetworkId &networkid, CoreSession *session);
    ~CoreNetwork();
    inline virtual const QMetaObject *syncMetaObject() const { return &Network::staticMetaObject; }

    inline CoreIdentity *identityPtr() const { return coreSession()->identity(identity()); }
    inline CoreSession *coreSession() const { return _coreSession; }
    inline CoreNetworkConfig *networkConfig() const { return coreSession()->networkConfig(); }

    inline CoreUserInputHandler *userInputHandler() const { return _userInputHandler; }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -40,6 +40,8 @@
 
 #include "coresession.h"
 
+#include <functional>
+
 class CoreIdentity;
 class CoreUserInputHandler;
 class CoreIgnoreListManager;
@@ -93,6 +95,8 @@
     inline quint16 localPort() const { return socket.localPort(); }
     inline quint16 peerPort() const { return socket.peerPort(); }
 
+    QList<QList<QByteArray>> splitMessage(const QString &cmd, const QString &message, std::function<QList<QByteArray>(QString &)> cmdGenerator);
+
 public slots:
     virtual void setMyNick(const QString &mynick);
 
@@ -112,6 +116,7 @@
     void userInput(BufferInfo bufferInfo, QString msg);
     void putRawLine(QByteArray input);
     void putCmd(const QString &cmd, const QList<QByteArray> &params, const QByteArray &prefix = QByteArray());
+    void putCmd(const QString &cmd, const QList<QList<QByteArray>> &params, const QByteArray &prefix = QByteArray());
 
     void setChannelJoined(const QString &channel);
     void setChannelParted(const QString &channel);
```
