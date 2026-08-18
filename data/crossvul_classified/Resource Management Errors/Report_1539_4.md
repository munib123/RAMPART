# CrossVul Fix Pair: Resource Management Errors in cpp
**Pair ID:** 1539_4
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1539_4`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```cpp
Lines 456-496 of the vulnerable file.

        if (params[0] == "-reset" && params.count() == 1) {
            // FIXME: give feedback to the user (I don't want to add new strings right now)
            network()->resetPersistentModes();
            return;
        }
    }

    // TODO handle correct encoding for buffer modes (channelEncode())
    emit putCmd("MODE", serverEncode(params));
}


// TODO: show privmsgs
void CoreUserInputHandler::handleMsg(const BufferInfo &bufferInfo, const QString &msg)
{
    Q_UNUSED(bufferInfo);
    if (!msg.contains(' '))
        return;

    QString target = msg.section(' ', 0, 0);
    QByteArray encMsg = userEncode(target, msg.section(' ', 1));

#ifdef HAVE_QCA2
    putPrivmsg(serverEncode(target), encMsg, network()->cipher(target));
#else
    putPrivmsg(serverEncode(target), encMsg);
#endif
}


void CoreUserInputHandler::handleNick(const BufferInfo &bufferInfo, const QString &msg)
{
    Q_UNUSED(bufferInfo)
    QString nick = msg.section(' ', 0, 0);
    emit putCmd("NICK", serverEncode(nick));
}


void CoreUserInputHandler::handleNotice(const BufferInfo &bufferInfo, const QString &msg)
{
    QString bufferName = msg.section(' ', 0, 0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -473,12 +473,16 @@
         return;
 
     QString target = msg.section(' ', 0, 0);
-    QByteArray encMsg = userEncode(target, msg.section(' ', 1));
+    QString msgSection = msg.section(' ', 1);
+
+    std::function<QByteArray(const QString &, const QString &)> encodeFunc = [this] (const QString &target, const QString &message) -> QByteArray {
+        return userEncode(target, message);
+    };
 
 #ifdef HAVE_QCA2
-    putPrivmsg(serverEncode(target), encMsg, network()->cipher(target));
+    putPrivmsg(target, msgSection, encodeFunc, network()->cipher(target));
 #else
-    putPrivmsg(serverEncode(target), encMsg);
+    putPrivmsg(target, msgSection, encodeFunc);
 #endif
 }
 
@@ -594,11 +598,14 @@
     if (bufferInfo.bufferName().isEmpty() || !bufferInfo.acceptsRegularMessages())
         return;  // server buffer
 
-    QByteArray encMsg = channelEncode(bufferInfo.bufferName(), msg);
+    std::function<QByteArray(const QString &, const QString &)> encodeFunc = [this] (const QString &target, const QString &message) -> QByteArray {
+        return channelEncode(target, message);
+    };
+
 #ifdef HAVE_QCA2
-    putPrivmsg(serverEncode(bufferInfo.bufferName()), encMsg, network()->cipher(bufferInfo.bufferName()));
+    putPrivmsg(bufferInfo.bufferName(), msg, encodeFunc, network()->cipher(bufferInfo.bufferName()));
 #else
-    putPrivmsg(serverEncode(bufferInfo.bufferName()), encMsg);
+    putPrivmsg(bufferInfo.bufferName(), msg, encodeFunc);
 #endif
     emit displayMsg(Message::Plain, bufferInfo.type(), bufferInfo.bufferName(), msg, network()->myNick(), Message::Self);
 }
@@ -763,56 +770,23 @@
 }
 
 
-void CoreUserInputHandler::putPrivmsg(const QByteArray &target, const QByteArray &message, Cipher *cipher)
-{
-    // Encrypted messages need special care. There's no clear relation between cleartext and encrypted message length,
-    // so we can't just compute the maxSplitPos. Instead, we need to loop through the splitpoints until the crypted
-    // version is short enough...
-    // TODO: check out how the various possible encryption methods behave length-wise and make
-    //       this clean by predicting the length of the crypted msg.
-    //       For example, blowfish-ebc seems to create 8-char chunks.
-
-    static const char *cmd = "PRIVMSG";
-    static const char *splitter = " .,-!?";
-
-    int maxSplitPos = message.count();
-    int splitPos = maxSplitPos;
-    forever {
-        QByteArray crypted = message.left(splitPos);
-        bool isEncrypted = false;
+void CoreUserInputHandler::putPrivmsg(const QString &target, const QString &message, std::function<QByteArray(const QString &, const QString &)> encodeFunc, Cipher *cipher)
+{
+    QString cmd("PRIVMSG");
+    QByteArray targetEnc = serverEncode(target);
+
+    std::function<QList<QByteArray>(QString &)> cmdGenerator = [&] (QString &splitMsg) -> QList<QByteArray> {
+        QByteArray splitMsgEnc = encodeFunc(target, splitMsg);
+
 #ifdef HAVE_QCA2
-        if (cipher && !cipher->key().isEmpty() && !message.isEmpty()) {
-            isEncrypted = cipher->encrypt(crypted);
+        if (cipher && !cipher->key().isEmpty() && !splitMsg.isEmpty()) {
+            cipher->encrypt(splitMsgEnc);
         }
 #endif
-        int overrun = lastParamOverrun(cmd, QList<QByteArray>() << target << crypted);
-        if (overrun) {
-            // In case this is not an encrypted msg, we can just cut off at the end
-            if (!isEncrypted)
-                maxSplitPos = message.count() - overrun;
-
-            splitPos = -1;
-            for (const char *splitChar = splitter; *splitChar != 0; splitChar++) {
-                splitPos = qMax(splitPos, message.lastIndexOf(*splitChar, maxSplitPos) + 1); // keep split char on old line
-            }
-            if (splitPos <= 0 || splitPos > maxSplitPos)
-                splitPos = maxSplitPos;
-
-            maxSplitPos = splitPos - 1;
-            if (maxSplitPos <= 0) { // this should never happen, but who knows...
-                qWarning() << tr("[Error] Could not encrypt your message: %1").arg(message.data());
-                return;
-            }
-            continue; // we never come back here for !encrypted!
-        }
-
-        // now we have found a valid splitpos (or didn't need to split to begin with)
-        putCmd(cmd, QList<QByteArray>() << target << crypted);
-        if (splitPos < message.count())
-            putPrivmsg(target, message.mid(splitPos), cipher);
-
-        return;
-    }
+        return QList<QByteArray>() << targetEnc << splitMsgEnc;
+    };
+
+    putCmd(cmd, network()->splitMessage(cmd, message, cmdGenerator));
 }
 
 
```
