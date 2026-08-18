# CrossVul Fix Pair: Improper Authentication in c
**Pair ID:** 5267_0
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5267_0`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```c
Lines 213-253 of the vulnerable file.


/*
 * AUTHENTICATE message
 *
 * parv[1]: data
 */
CMD_FUNC(m_authenticate)
{
	aClient *agent_p = NULL;

	/* Failing to use CAP REQ for sasl is a protocol violation. */
	if (!SASL_SERVER || !MyConnect(sptr) || BadPtr(parv[1]) || !CHECKPROTO(sptr, PROTO_SASL))
		return 0;

	if (sptr->local->sasl_complete)
	{
		sendto_one(sptr, err_str(ERR_SASLALREADY), me.name, BadPtr(sptr->name) ? "*" : sptr->name);
		return 0;
	}

	if (strlen(parv[1]) > 400)
	{
		sendto_one(sptr, err_str(ERR_SASLTOOLONG), me.name, BadPtr(sptr->name) ? "*" : sptr->name);
		return 0;
	}

	if (*sptr->local->sasl_agent)
		agent_p = find_client(sptr->local->sasl_agent, NULL);

	if (agent_p == NULL)
	{
		char *addr = BadPtr(sptr->ip) ? "0" : sptr->ip;
		char *certfp = moddata_client_get(sptr, "certfp");

		sendto_server(NULL, 0, 0, ":%s SASL %s %s H %s %s",
		    me.name, SASL_SERVER, encode_puid(sptr), addr, addr);

		if (certfp)
			sendto_server(NULL, 0, 0, ":%s SASL %s %s S %s %s",
			    me.name, SASL_SERVER, encode_puid(sptr), parv[1], certfp);
		else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -230,6 +230,12 @@
 		return 0;
 	}
 
+	if ((parv[1][0] == ':') || strchr(parv[1], ' '))
+	{
+		sendto_one(sptr, err_str(ERR_CANNOTDOCOMMAND), me.name, "*", "AUTHENTICATE", "Invalid parameter");
+		return 0;
+	}
+
 	if (strlen(parv[1]) > 400)
 	{
 		sendto_one(sptr, err_str(ERR_SASLTOOLONG), me.name, BadPtr(sptr->name) ? "*" : sptr->name);
```
