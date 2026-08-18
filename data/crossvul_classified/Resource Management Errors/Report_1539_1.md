# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1539_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1539_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 38-73 of the vulnerable file.

public:
    CoreBasicHandler(CoreNetwork *parent = 0);

    QString serverDecode(const QByteArray &string);
    QStringList serverDecode(const QList<QByteArray> &stringlist);
    QString channelDecode(const QString &bufferName, const QByteArray &string);
    QStringList channelDecode(const QString &bufferName, const QList<QByteArray> &stringlist);
    QString userDecode(const QString &userNick, const QByteArray &string);
    QStringList userDecode(const QString &userNick, const QList<QByteArray> &stringlist);

    QByteArray serverEncode(const QString &string);
    QList<QByteArray> serverEncode(const QStringList &stringlist);
    QByteArray channelEncode(const QString &bufferName, const QString &string);
    QList<QByteArray> channelEncode(const QString &bufferName, const QStringList &stringlist);
    QByteArray userEncode(const QString &userNick, const QString &string);
    QList<QByteArray> userEncode(const QString &userNick, const QStringList &stringlist);

signals:
    void displayMsg(Message::Type, BufferInfo::Type, const QString &target, const QString &text, const QString &sender = "", Message::Flags flags = Message::None);
    void putCmd(const QString &cmd, const QList<QByteArray> &params, const QByteArray &prefix = QByteArray());
    void putRawLine(const QByteArray &msg);

protected:
    void putCmd(const QString &cmd, const QByteArray &param, const QByteArray &prefix = QByteArray());

    inline CoreNetwork *network() const { return _network; }
    inline CoreSession *coreSession() const { return _network->coreSession(); }

    BufferInfo::Type typeByTarget(const QString &target) const;

private:
    CoreNetwork *_network;
};


#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,6 +55,7 @@
 signals:
     void displayMsg(Message::Type, BufferInfo::Type, const QString &target, const QString &text, const QString &sender = "", Message::Flags flags = Message::None);
     void putCmd(const QString &cmd, const QList<QByteArray> &params, const QByteArray &prefix = QByteArray());
+    void putCmd(const QString &cmd, const QList<QList<QByteArray>> &params, const QByteArray &prefix = QByteArray());
     void putRawLine(const QByteArray &msg);
 
 protected:
```
