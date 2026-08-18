# CrossVul Fix Pair: DEPRECATED: Code in cpp
**Pair ID:** 1789_0
**Vulnerability Class:** DEPRECATED- Code
**CWE:** CWE-17
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1789_0`)

## Vulnerability Information & PoC

## Description
DEPRECATED: Code

## Vulnerable Code
```cpp
Lines 211-251 of the vulnerable file.

    network()->setCipherKey(target, QByteArray());
    emit displayMsg(Message::Info, typeByTarget(bufname), bufname, tr("The key for %1 has been deleted.").arg(target));

#else
    Q_UNUSED(msg)
    emit displayMsg(Message::Error, typeByTarget(bufname), bufname, tr("Error: Setting an encryption key requires Quassel to have been built "
                                                                    "with support for the Qt Cryptographic Architecture (QCA2) library. "
                                                                    "Contact your distributor about a Quassel package with QCA2 "
                                                                    "support, or rebuild Quassel with QCA2 present."));
#endif
}

void CoreUserInputHandler::doMode(const BufferInfo &bufferInfo, const QChar& addOrRemove, const QChar& mode, const QString &nicks)
{
    QString m;
    bool isNumber;
    int maxModes = network()->support("MODES").toInt(&isNumber);
    if (!isNumber || maxModes == 0) maxModes = 1;

    QStringList nickList;
    if (nicks == "*") { // All users in channel
        const QList<IrcUser*> users = network()->ircChannel(bufferInfo.bufferName())->ircUsers();
        foreach(IrcUser *user, users) {
            if ((addOrRemove == '+' && !network()->ircChannel(bufferInfo.bufferName())->userModes(user).contains(mode))
                || (addOrRemove == '-' && network()->ircChannel(bufferInfo.bufferName())->userModes(user).contains(mode)))
                nickList.append(user->nick());
        }
    } else {
        nickList = nicks.split(' ', QString::SkipEmptyParts);
    }

    if (nickList.count() == 0) return;

    while (!nickList.isEmpty()) {
        int amount = qMin(nickList.count(), maxModes);
        QString m = addOrRemove; for(int i = 0; i < amount; i++) m += mode;
        QStringList params;
        params << bufferInfo.bufferName() << m;
        for(int i = 0; i < amount; i++) params << nickList.takeFirst();
        emit putCmd("MODE", serverEncode(params));
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -228,7 +228,7 @@
     if (!isNumber || maxModes == 0) maxModes = 1;
 
     QStringList nickList;
-    if (nicks == "*") { // All users in channel
+    if (nicks == "*" && bufferInfo.type() == BufferInfo::ChannelBuffer) { // All users in channel
         const QList<IrcUser*> users = network()->ircChannel(bufferInfo.bufferName())->ircUsers();
         foreach(IrcUser *user, users) {
             if ((addOrRemove == '+' && !network()->ircChannel(bufferInfo.bufferName())->userModes(user).contains(mode))
```
