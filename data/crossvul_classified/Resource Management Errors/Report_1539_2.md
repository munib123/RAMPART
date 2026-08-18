# CrossVul Fix Pair: Resource Management Errors in cpp
**Pair ID:** 1539_2
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1539_2`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```cpp
Lines 264-304 of the vulnerable file.



void CoreNetwork::putCmd(const QString &cmd, const QList<QByteArray> &params, const QByteArray &prefix)
{
    QByteArray msg;

    if (!prefix.isEmpty())
        msg += ":" + prefix + " ";
    msg += cmd.toUpper().toLatin1();

    for (int i = 0; i < params.size(); i++) {
        msg += " ";

        if (i == params.size() - 1 && (params[i].contains(' ') || (!params[i].isEmpty() && params[i][0] == ':')))
            msg += ":";

        msg += params[i];
    }

    putRawLine(msg);
}


void CoreNetwork::setChannelJoined(const QString &channel)
{
    _autoWhoQueue.prepend(channel.toLower()); // prepend so this new chan is the first to be checked

    Core::setChannelPersistent(userId(), networkId(), channel, true);
    Core::setPersistentChannelKey(userId(), networkId(), channel, _channelKeys[channel.toLower()]);
}


void CoreNetwork::setChannelParted(const QString &channel)
{
    removeChannelKey(channel);
    _autoWhoQueue.removeAll(channel.toLower());
    _autoWhoPending.remove(channel.toLower());

    Core::setChannelPersistent(userId(), networkId(), channel, false);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -284,6 +284,16 @@
 }
 
 
+void CoreNetwork::putCmd(const QString &cmd, const QList<QList<QByteArray>> &params, const QByteArray &prefix)
+{
+    QListIterator<QList<QByteArray>> i(params);
+    while (i.hasNext()) {
+        QList<QByteArray> msg = i.next();
+        putCmd(cmd, msg, prefix);
+    }
+}
+
+
 void CoreNetwork::setChannelJoined(const QString &channel)
 {
     _autoWhoQueue.prepend(channel.toLower()); // prepend so this new chan is the first to be checked
@@ -980,3 +990,79 @@
         }
     }
 }
+
+
+QList<QList<QByteArray>> CoreNetwork::splitMessage(const QString &cmd, const QString &message, std::function<QList<QByteArray>(QString &)> cmdGenerator)
+{
+    QString wrkMsg(message);
+    QList<QList<QByteArray>> msgsToSend;
+
+    // do while (wrkMsg.size() > 0)
+    do {
+        // First, check to see if the whole message can be sent at once.  The
+        // cmdGenerator function is passed in by the caller and is used to encode
+        // and encrypt (if applicable) the message, since different callers might
+        // want to use different encoding or encode different values.
+        int splitPos = wrkMsg.size();
+        QList<QByteArray> initialSplitMsgEnc = cmdGenerator(wrkMsg);
+        int initialOverrun = userInputHandler()->lastParamOverrun(cmd, initialSplitMsgEnc);
+
+        if (initialOverrun) {
+            // If the message was too long to be sent, first try splitting it along
+            // word boundaries with QTextBoundaryFinder.
+            QString splitMsg(wrkMsg);
+            QTextBoundaryFinder qtbf(QTextBoundaryFinder::Word, splitMsg);
+            qtbf.setPosition(initialSplitMsgEnc[1].size() - initialOverrun);
+            QList<QByteArray> splitMsgEnc;
+            int overrun = initialOverrun;
+
+            while (overrun) {
+                splitPos = qtbf.toPreviousBoundary();
+
+                // splitPos==-1 means the QTBF couldn't find a split point at all and
+                // splitPos==0 means the QTBF could only find a boundary at the beginning of
+                // the string.  Neither one of these works for us.
+                if (splitPos > 0) {
+                    // If a split point could be found, split the message there, calculate the
+                    // overrun, and continue with the loop.
+                    splitMsg = splitMsg.left(splitPos);
+                    splitMsgEnc = cmdGenerator(splitMsg);
+                    overrun = userInputHandler()->lastParamOverrun(cmd, splitMsgEnc);
+                }
+                else {
+                    // If a split point could not be found (the beginning of the message
+                    // is reached without finding a split point short enough to send) and we
+                    // are still in Word mode, switch to Grapheme mode.  We also need to restore
+                    // the full wrkMsg to splitMsg, since splitMsg may have been cut down during
+                    // the previous attempt to find a split point.
+                    if (qtbf.type() == QTextBoundaryFinder::Word) {
+                        splitMsg = wrkMsg;
+                        splitPos = splitMsg.size();
+                        QTextBoundaryFinder graphemeQtbf(QTextBoundaryFinder::Grapheme, splitMsg);
+                        graphemeQtbf.setPosition(initialSplitMsgEnc[1].size() - initialOverrun);
+                        qtbf = graphemeQtbf;
+                    }
+                    else {
+                        // If the QTBF fails to find a split point in Grapheme mode, we give up.
+                        // This should never happen, but it should be handled anyway.
+                        qWarning() << "Unexpected failure to split message!";
+                        return msgsToSend;
+                    }
+                }
+            }
+
+            // Once a message of sendable length has been found, remove it from the wrkMsg and
+            // add it to the list of messages to be sent.
+            wrkMsg.remove(0, splitPos);
+            msgsToSend.append(splitMsgEnc);
+        }
+        else{
+            // If the entire remaining message is short enough to be sent all at once, remove
+            // it from the wrkMsg and add it to the list of messages to be sent.
+            wrkMsg.remove(0, splitPos);
+            msgsToSend.append(initialSplitMsgEnc);
+        }
+    } while (wrkMsg.size() > 0);
+
+    return msgsToSend;
+}
```
