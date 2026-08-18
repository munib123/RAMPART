# CrossVul Fix Pair: NULL Pointer Dereference in cpp
**Pair ID:** 4037_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4037_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```cpp
Lines 872-912 of the vulnerable file.


    CChan* pChan = m_pNetwork->FindChan(sTarget);
    if (pChan) {
        if (!pChan->AutoClearChanBuffer() || !m_pNetwork->IsUserOnline()) {
            pChan->AddBuffer(Format, Message.GetText());
        }
    } else if (Message.GetType() != CMessage::Type::Notice) {
        if (!m_pUser->AutoClearQueryBuffer() || !m_pNetwork->IsUserOnline()) {
            CQuery* pQuery = m_pNetwork->AddQuery(sTarget);
            if (pQuery) {
                pQuery->AddBuffer(Format, Message.GetText());
            }
        }
    }
}

void CClient::EchoMessage(const CMessage& Message) {
    CMessage EchoedMessage = Message;
    for (CClient* pClient : GetClients()) {
        if (pClient->HasEchoMessage() ||
            (pClient != this && (m_pNetwork->IsChan(Message.GetParam(0)) ||
                                 pClient->HasSelfMessage()))) {
            EchoedMessage.SetNick(GetNickMask());
            pClient->PutClient(EchoedMessage);
        }
    }
}

set<CChan*> CClient::MatchChans(const CString& sPatterns) const {
    VCString vsPatterns;
    sPatterns.Replace_n(",", " ")
        .Split(" ", vsPatterns, false, "", "", true, true);

    set<CChan*> sChans;
    for (const CString& sPattern : vsPatterns) {
        vector<CChan*> vChans = m_pNetwork->FindChans(sPattern);
        sChans.insert(vChans.begin(), vChans.end());
    }
    return sChans;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -889,7 +889,7 @@
     CMessage EchoedMessage = Message;
     for (CClient* pClient : GetClients()) {
         if (pClient->HasEchoMessage() ||
-            (pClient != this && (m_pNetwork->IsChan(Message.GetParam(0)) ||
+            (pClient != this && ((m_pNetwork && m_pNetwork->IsChan(Message.GetParam(0))) ||
                                  pClient->HasSelfMessage()))) {
             EchoedMessage.SetNick(GetNickMask());
             pClient->PutClient(EchoedMessage);
```
