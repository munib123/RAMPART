# CrossVul Fix Pair: Resource Management Errors in cpp
**Pair ID:** 1539_6
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1539_6`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```cpp
Lines 295-336 of the vulnerable file.

    }
    else if (e->type() == EventManager::CtcpEventFlush && _replies.contains(e->uuid())) {
        CtcpReply reply = _replies.take(e->uuid());
        if (reply.replies.count())
            packedReply(net, reply.bufferName, reply.replies);
    }
}


QByteArray CtcpParser::pack(const QByteArray &ctcpTag, const QByteArray &message)
{
    if (message.isEmpty())
        return XDELIM + ctcpTag + XDELIM;

    return XDELIM + ctcpTag + ' ' + xdelimQuote(message) + XDELIM;
}


void CtcpParser::query(CoreNetwork *net, const QString &bufname, const QString &ctcpTag, const QString &message)
{
    QList<QByteArray> params;
    params << net->serverEncode(bufname) << lowLevelQuote(pack(net->serverEncode(ctcpTag), net->userEncode(bufname, message)));

    static const char *splitter = " .,-!?";
    int maxSplitPos = message.count();
    int splitPos = maxSplitPos;

    int overrun = net->userInputHandler()->lastParamOverrun("PRIVMSG", params);
    if (overrun) {
        maxSplitPos = message.count() - overrun -2;
        splitPos = -1;
        for (const char *splitChar = splitter; *splitChar != 0; splitChar++) {
            splitPos = qMax(splitPos, message.lastIndexOf(*splitChar, maxSplitPos) + 1); // keep split char on old line
        }
        if (splitPos <= 0 || splitPos > maxSplitPos)
            splitPos = maxSplitPos;

        params = params.mid(0, 1) <<  lowLevelQuote(pack(net->serverEncode(ctcpTag), net->userEncode(bufname, message.left(splitPos))));
    }
    net->putCmd("PRIVMSG", params);

    if (splitPos < message.count())
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -312,29 +312,13 @@
 
 void CtcpParser::query(CoreNetwork *net, const QString &bufname, const QString &ctcpTag, const QString &message)
 {
-    QList<QByteArray> params;
-    params << net->serverEncode(bufname) << lowLevelQuote(pack(net->serverEncode(ctcpTag), net->userEncode(bufname, message)));
-
-    static const char *splitter = " .,-!?";
-    int maxSplitPos = message.count();
-    int splitPos = maxSplitPos;
-
-    int overrun = net->userInputHandler()->lastParamOverrun("PRIVMSG", params);
-    if (overrun) {
-        maxSplitPos = message.count() - overrun -2;
-        splitPos = -1;
-        for (const char *splitChar = splitter; *splitChar != 0; splitChar++) {
-            splitPos = qMax(splitPos, message.lastIndexOf(*splitChar, maxSplitPos) + 1); // keep split char on old line
-        }
-        if (splitPos <= 0 || splitPos > maxSplitPos)
-            splitPos = maxSplitPos;
-
-        params = params.mid(0, 1) <<  lowLevelQuote(pack(net->serverEncode(ctcpTag), net->userEncode(bufname, message.left(splitPos))));
-    }
-    net->putCmd("PRIVMSG", params);
-
-    if (splitPos < message.count())
-        query(net, bufname, ctcpTag, message.mid(splitPos));
+    QString cmd("PRIVMSG");
+
+    std::function<QList<QByteArray>(QString &)> cmdGenerator = [&] (QString &splitMsg) -> QList<QByteArray> {
+        return QList<QByteArray>() << net->serverEncode(bufname) << lowLevelQuote(pack(net->serverEncode(ctcpTag), net->userEncode(bufname, splitMsg)));
+    };
+
+    net->putCmd(cmd, net->splitMessage(cmd, message, cmdGenerator));
 }
 
 
```
