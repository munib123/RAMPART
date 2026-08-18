# CrossVul Fix Pair: Resource Management Errors in cpp
**Pair ID:** 3566_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3566_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```cpp
Lines 221-261 of the vulnerable file.

				if (uBNCPort) {
					CString sIP = GetLocalDCCIP();
					m_pUser->PutUser(":" + Nick.GetNickMask() + " PRIVMSG " + m_pUser->GetNick() + " :\001DCC CHAT chat " + CString(CUtils::GetLongIP(sIP)) + " " + CString(uBNCPort) + "\001");
				}
			} else if (sType.Equals("SEND")) {
				// DCC SEND readme.txt 403120438 5550 1104
				unsigned short uBNCPort = CDCCBounce::DCCRequest(Nick.GetNick(), uLongIP, uPort, sFile, false, this, CUtils::GetIP(uLongIP));
				if (uBNCPort) {
					CString sIP = GetLocalDCCIP();
					m_pUser->PutUser(":" + Nick.GetNickMask() + " PRIVMSG " + m_pUser->GetNick() + " :\001DCC SEND " + sFile + " " + CString(CUtils::GetLongIP(sIP)) + " " + CString(uBNCPort) + " " + CString(uFileSize) + "\001");
				}
			} else if (sType.Equals("RESUME")) {
				// Need to lookup the connection by port, filter the port, and forward to the user
				unsigned short uResumePort = sMessage.Token(3).ToUShort();

				set<CSocket*>::const_iterator it;
				for (it = BeginSockets(); it != EndSockets(); ++it) {
					CDCCBounce* pSock = (CDCCBounce*) *it;

					if (pSock->GetLocalPort() == uResumePort) {
						m_pUser->PutUser(":" + Nick.GetNickMask() + " PRIVMSG " + m_pClient->GetNick() + " :\001DCC " + sType + " " + sFile + " " + CString(pSock->GetUserPort()) + " " + sMessage.Token(4) + "\001");
					}
				}
			} else if (sType.Equals("ACCEPT")) {
				// Need to lookup the connection by port, filter the port, and forward to the user
				set<CSocket*>::const_iterator it;
				for (it = BeginSockets(); it != EndSockets(); ++it) {
					CDCCBounce* pSock = (CDCCBounce*) *it;

					if (pSock->GetUserPort() == sMessage.Token(3).ToUShort()) {
						m_pUser->PutUser(":" + Nick.GetNickMask() + " PRIVMSG " + m_pClient->GetNick() + " :\001DCC " + sType + " " + sFile + " " + CString(pSock->GetLocalPort()) + " " + sMessage.Token(4) + "\001");
					}
				}
			}

			return HALTCORE;
		}

		return CONTINUE;
	}
};
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -238,7 +238,7 @@
 					CDCCBounce* pSock = (CDCCBounce*) *it;
 
 					if (pSock->GetLocalPort() == uResumePort) {
-						m_pUser->PutUser(":" + Nick.GetNickMask() + " PRIVMSG " + m_pClient->GetNick() + " :\001DCC " + sType + " " + sFile + " " + CString(pSock->GetUserPort()) + " " + sMessage.Token(4) + "\001");
+						m_pUser->PutUser(":" + Nick.GetNickMask() + " PRIVMSG " + m_pUser->GetNick() + " :\001DCC " + sType + " " + sFile + " " + CString(pSock->GetUserPort()) + " " + sMessage.Token(4) + "\001");
 					}
 				}
 			} else if (sType.Equals("ACCEPT")) {
@@ -248,7 +248,7 @@
 					CDCCBounce* pSock = (CDCCBounce*) *it;
 
 					if (pSock->GetUserPort() == sMessage.Token(3).ToUShort()) {
-						m_pUser->PutUser(":" + Nick.GetNickMask() + " PRIVMSG " + m_pClient->GetNick() + " :\001DCC " + sType + " " + sFile + " " + CString(pSock->GetLocalPort()) + " " + sMessage.Token(4) + "\001");
+						m_pUser->PutUser(":" + Nick.GetNickMask() + " PRIVMSG " + m_pUser->GetNick() + " :\001DCC " + sType + " " + sFile + " " + CString(pSock->GetLocalPort()) + " " + sMessage.Token(4) + "\001");
 					}
 				}
 			}
```
