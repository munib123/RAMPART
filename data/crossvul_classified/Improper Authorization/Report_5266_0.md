# CrossVul Fix Pair: Improper Authorization in c
**Pair ID:** 5266_0
**Vulnerability Class:** Improper Authorization
**CWE:** CWE-285
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5266_0`)

## Vulnerability Information & PoC

## Description
Improper Authorization - Assuming a user with a given identity, authorization is the process of determining whether that user can access a given resource, based on the user's privileges and any permissions or other access-...

## Vulnerable Code
```c
Lines 71-111 of the vulnerable file.

	{ "client_exit",	(hookfn) advertise_sasl_exit },
	{ NULL, NULL }
};

DECLARE_MODULE_AV1(sasl, NULL, NULL, sasl_clist, NULL, sasl_hfnlist, "$Revision: 1409 $");

static int
m_authenticate(struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	struct Client *agent_p = NULL;
	struct Client *saslserv_p = NULL;

	/* They really should use CAP for their own sake. */
	if(!IsCapable(source_p, CLICAP_SASL))
		return 0;

	if (strlen(client_p->id) == 3)
	{
		exit_client(client_p, client_p, client_p, "Mixing client and server protocol");
		return 0;
	}

	saslserv_p = find_named_client(ConfigFileEntry.sasl_service);
	if (saslserv_p == NULL || !IsService(saslserv_p))
	{
		sendto_one(source_p, form_str(ERR_SASLABORTED), me.name, EmptyString(source_p->name) ? "*" : source_p->name);
		return 0;
	}

	if(source_p->localClient->sasl_complete)
	{
		*source_p->localClient->sasl_agent = '\0';
		source_p->localClient->sasl_complete = 0;
	}

	if(strlen(parv[1]) > 400)
	{
		sendto_one(source_p, form_str(ERR_SASLTOOLONG), me.name, EmptyString(source_p->name) ? "*" : source_p->name);
		return 0;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,6 +91,12 @@
 		return 0;
 	}
 
+	if (*parv[1] == ':' || strchr(parv[1], ' '))
+	{
+		exit_client(client_p, client_p, client_p, "Malformed AUTHENTICATE");
+		return 0;
+	}
+
 	saslserv_p = find_named_client(ConfigFileEntry.sasl_service);
 	if (saslserv_p == NULL || !IsService(saslserv_p))
 	{
```
