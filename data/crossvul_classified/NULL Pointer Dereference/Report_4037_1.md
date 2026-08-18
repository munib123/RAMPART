# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 4037_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4037_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 280-303 of the vulnerable file.

    ircd.Write(":server 001 nick :Hello");
    client.Write("JOIN #znc secret");
    ircd.ReadUntil("JOIN #znc secret");
    ircd.Write(":nick JOIN :#znc");
    client.ReadUntil("JOIN :#znc");
    ircd.Close();

    ircd = ConnectIRCd();
    ircd.Write(":server 001 nick :Hello");
    ircd.ReadUntil("JOIN #znc secret");
}

TEST_F(ZNCTest, StatusEchoMessage) {
    auto znc = Run();
    auto ircd = ConnectIRCd();
    auto client = LoginClient();
    client.Write("CAP REQ :echo-message");
    client.Write("PRIVMSG *status :blah");
    client.ReadUntil(":nick!user@irc.znc.in PRIVMSG *status :blah");
    client.ReadUntil(":*status!znc@znc.in PRIVMSG nick :Unknown command");
}

}  // namespace
}  // namespace znc_inttest
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -297,6 +297,14 @@
     client.Write("PRIVMSG *status :blah");
     client.ReadUntil(":nick!user@irc.znc.in PRIVMSG *status :blah");
     client.ReadUntil(":*status!znc@znc.in PRIVMSG nick :Unknown command");
+    client.Write("znc delnetwork test");
+    client.ReadUntil("Network deleted");
+    auto client2 = LoginClient();
+    client2.Write("PRIVMSG *status :blah2");
+    client2.ReadUntil(":*status!znc@znc.in PRIVMSG nick :Unknown command");
+    auto client3 = LoginClient();
+    client3.Write("PRIVMSG *status :blah3");
+    client3.ReadUntil(":*status!znc@znc.in PRIVMSG nick :Unknown command");
 }
 
 }  // namespace
```
