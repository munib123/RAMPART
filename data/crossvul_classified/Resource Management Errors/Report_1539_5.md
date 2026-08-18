# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1539_5
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1539_5`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 71-108 of the vulnerable file.

    void handleSetkey(const BufferInfo &bufferInfo, const QString &text);
    void handleShowkey(const BufferInfo &bufferInfo, const QString &text);
    void handleTopic(const BufferInfo &bufferInfo, const QString &text);
    void handleVoice(const BufferInfo &bufferInfo, const QString &text);
    void handleWait(const BufferInfo &bufferInfo, const QString &text);
    void handleWho(const BufferInfo &bufferInfo, const QString &text);
    void handleWhois(const BufferInfo &bufferInfo, const QString &text);
    void handleWhowas(const BufferInfo &bufferInfo, const QString &text);

    void defaultHandler(QString cmd, const BufferInfo &bufferInfo, const QString &text);

    void issueQuit(const QString &reason);
    void issueAway(const QString &msg, bool autoCheck = true);

protected:
    void timerEvent(QTimerEvent *event);

private:
    void doMode(const BufferInfo& bufferInfo, const QChar &addOrRemove, const QChar &mode, const QString &nickList);
    void banOrUnban(const BufferInfo &bufferInfo, const QString &text, bool ban);
    void putPrivmsg(const QByteArray &target, const QByteArray &message, Cipher *cipher = 0);

#ifdef HAVE_QCA2
    QByteArray encrypt(const QString &target, const QByteArray &message, bool *didEncrypt = 0) const;
#endif

    struct Command {
        BufferInfo bufferInfo;
        QString command;
        Command(const BufferInfo &info, const QString &command) : bufferInfo(info), command(command) {}
        Command() {}
    };

    QHash<int, Command> _delayedCommands;
};


#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,7 +88,7 @@
 private:
     void doMode(const BufferInfo& bufferInfo, const QChar &addOrRemove, const QChar &mode, const QString &nickList);
     void banOrUnban(const BufferInfo &bufferInfo, const QString &text, bool ban);
-    void putPrivmsg(const QByteArray &target, const QByteArray &message, Cipher *cipher = 0);
+    void putPrivmsg(const QString &target, const QString &message, std::function<QByteArray(const QString &, const QString &)> encodeFunc, Cipher *cipher = 0);
 
 #ifdef HAVE_QCA2
     QByteArray encrypt(const QString &target, const QByteArray &message, bool *didEncrypt = 0) const;
```
