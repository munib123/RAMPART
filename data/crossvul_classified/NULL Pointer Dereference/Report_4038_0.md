# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 4038_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4038_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 1217-1257 of the vulnerable file.

    }
    // Don't forward this msg.  We don't want the client getting us
    // disconnected.
    return true;
}

bool CClient::OnTextMessage(CTextMessage& Message) {
    CString sTargets = Message.GetTarget();

    VCString vTargets;
    sTargets.Split(",", vTargets, false);

    for (CString& sTarget : vTargets) {
        Message.SetTarget(sTarget);
        if (m_pNetwork) {
            // May be nullptr.
            Message.SetChan(m_pNetwork->FindChan(sTarget));
        }

        if (sTarget.TrimPrefix(m_pUser->GetStatusPrefix())) {
            if (sTarget.Equals("status")) {
                CString sMsg = Message.GetText();
                UserCommand(sMsg);
            } else {
                CALLMOD(sTarget, this, m_pUser, m_pNetwork,
                        OnModCommand(Message.GetText()));
            }
            continue;
        }

        bool bContinue = false;
        NETWORKMODULECALL(OnUserTextMessage(Message), m_pUser, m_pNetwork, this,
                          &bContinue);
        if (bContinue) continue;

        if (!GetIRCSock()) {
            // Some lagmeters do a PRIVMSG to their own nick, ignore those.
            if (!sTarget.Equals(m_sNick))
                PutStatus(
                    t_f("Your message to {1} got lost, you are not connected "
                        "to IRC!")(Message.GetTarget()));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1234,6 +1234,8 @@
         }
 
         if (sTarget.TrimPrefix(m_pUser->GetStatusPrefix())) {
+            EchoMessage(Message);
+
             if (sTarget.Equals("status")) {
                 CString sMsg = Message.GetText();
                 UserCommand(sMsg);
```
