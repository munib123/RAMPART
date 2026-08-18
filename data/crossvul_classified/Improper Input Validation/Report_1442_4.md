# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1442_4
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1442_4`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 38-78 of the vulnerable file.


TEST_F(ZNCTest, Modpython) {
    if (QProcessEnvironment::systemEnvironment().value(
            "DISABLED_ZNC_PERL_PYTHON_TEST") == "1") {
        return;
    }
    auto znc = Run();
    znc->CanLeak();
    auto ircd = ConnectIRCd();
    auto client = LoginClient();
    client.Write("znc loadmod modpython");
    client.Write("znc loadmod pyeval");
    client.Write("PRIVMSG *pyeval :2+2");
    client.ReadUntil(":*pyeval!znc@znc.in PRIVMSG nick :4");
    client.Write("PRIVMSG *pyeval :module.GetUser().GetUserName()");
    client.ReadUntil("nick :'user'");
    ircd.Write(":server 001 nick :Hello");
    ircd.Write(":n!u@h PRIVMSG nick :Hi\xF0, github issue #1229");
    // "replacement character"
    client.ReadUntil("Hi\xEF\xBF\xBD, github issue");
}

TEST_F(ZNCTest, ModpythonSocket) {
    if (QProcessEnvironment::systemEnvironment().value(
            "DISABLED_ZNC_PERL_PYTHON_TEST") == "1") {
        return;
    }
    auto znc = Run();
    znc->CanLeak();

    InstallModule("socktest.py", R"(
        import znc

        class acc(znc.Socket):
            def OnReadData(self, data):
                self.GetModule().PutModule('received {} bytes'.format(len(data)))
                self.Close()

        class lis(znc.Socket):
            def OnAccepted(self, host, port):
                sock = self.GetModule().CreateSocket(acc)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -55,6 +55,13 @@
     ircd.Write(":n!u@h PRIVMSG nick :Hi\xF0, github issue #1229");
     // "replacement character"
     client.ReadUntil("Hi\xEF\xBF\xBD, github issue");
+
+    // Non-existing encoding
+    client.Write("PRIVMSG *controlpanel :Set ClientEncoding $me Western");
+    client.Write("JOIN #a\342");
+    client.ReadUntil(
+        ":*controlpanel!znc@znc.in PRIVMSG nick :ClientEncoding = UTF-8");
+    ircd.ReadUntil("JOIN #a\xEF\xBF\xBD");
 }
 
 TEST_F(ZNCTest, ModpythonSocket) {
```
