# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in cpp
**Pair ID:** 5265_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5265_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```cpp
Lines 172-212 of the vulnerable file.

		 case SASL_FAIL:
			this->user->WriteNumeric(904, "%s :SASL authentication failed", this->user->nick.c_str());
			break;
		 default:
			break;
		}

		this->state_announced = true;
	}
};

class CommandAuthenticate : public Command
{
 public:
	SimpleExtItem<SaslAuthenticator>& authExt;
	GenericCap& cap;
	CommandAuthenticate(Module* Creator, SimpleExtItem<SaslAuthenticator>& ext, GenericCap& Cap)
		: Command(Creator, "AUTHENTICATE", 1), authExt(ext), cap(Cap)
	{
		works_before_reg = true;
	}

	CmdResult Handle (const std::vector<std::string>& parameters, User *user)
	{
		/* Only allow AUTHENTICATE on unregistered clients */
		if (user->registered != REG_ALL)
		{
			if (!cap.ext.get(user))
				return CMD_FAILURE;

			SaslAuthenticator *sasl = authExt.get(user);
			if (!sasl)
				authExt.set(user, new SaslAuthenticator(user, parameters[0]));
			else if (sasl->SendClientMessage(parameters) == false)	// IAL abort extension --nenolod
			{
				sasl->AnnounceState();
				authExt.unset(user);
			}
		}
		return CMD_FAILURE;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -189,6 +189,7 @@
 		: Command(Creator, "AUTHENTICATE", 1), authExt(ext), cap(Cap)
 	{
 		works_before_reg = true;
+		allow_empty_last_param = false;
 	}
 
 	CmdResult Handle (const std::vector<std::string>& parameters, User *user)
@@ -197,6 +198,9 @@
 		if (user->registered != REG_ALL)
 		{
 			if (!cap.ext.get(user))
+				return CMD_FAILURE;
+
+			if (parameters[0].find(' ') != std::string::npos || parameters[0][0] == ':')
 				return CMD_FAILURE;
 
 			SaslAuthenticator *sasl = authExt.get(user);
```
