# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 2421_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2421_0`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 1-40 of the vulnerable file.

/*
 * Copyright (c) 2005-2007 William Pitcock, et al.
 * Rights to this code are as documented in doc/LICENSE.
 *
 * This file contains code for the CService FLAGS functions.
 *
 */

#include "atheme.h"
#include "template.h"

DECLARE_MODULE_V1
(
	"chanserv/flags", false, _modinit, _moddeinit,
	PACKAGE_STRING,
	"Atheme Development Group <http://www.atheme.org>"
);

static void cs_cmd_flags(sourceinfo_t *si, int parc, char *parv[]);

command_t cs_flags = { "FLAGS", N_("Manipulates specific permissions on a channel."),
                        AC_NONE, 3, cs_cmd_flags, { .path = "cservice/flags" } };

void _modinit(module_t *m)
{
	service_named_bind_command("chanserv", &cs_flags);
}

void _moddeinit(module_unload_intent_t intent)
{
	service_named_unbind_command("chanserv", &cs_flags);
}

typedef struct {
	const char *res;
	unsigned int level;
} template_iter_t;

static int global_template_search(const char *key, void *data, void *privdata)
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -17,18 +17,35 @@
 );
 
 static void cs_cmd_flags(sourceinfo_t *si, int parc, char *parv[]);
+static void check_registration_keywords(hook_user_register_check_t *hdata);
 
 command_t cs_flags = { "FLAGS", N_("Manipulates specific permissions on a channel."),
                         AC_NONE, 3, cs_cmd_flags, { .path = "cservice/flags" } };
 
+static bool anope_flags_compat = true;
+
 void _modinit(module_t *m)
 {
 	service_named_bind_command("chanserv", &cs_flags);
+
+	add_bool_conf_item("ANOPE_FLAGS_COMPAT", &chansvs.me->conf_table, 0, &anope_flags_compat, true);
+
+	hook_add_event("nick_can_register");
+	hook_add_nick_can_register(check_registration_keywords);
+
+	hook_add_event("user_can_register");
+	hook_add_user_can_register(check_registration_keywords);
 }
 
 void _moddeinit(module_unload_intent_t intent)
 {
 	service_named_unbind_command("chanserv", &cs_flags);
+
+	hook_del_nick_can_register(check_registration_keywords);
+
+	hook_del_user_can_register(check_registration_keywords);
+
+	del_conf_item("ANOPE_FLAGS_COMPAT", &chansvs.me->conf_table);
 }
 
 typedef struct {
@@ -148,6 +165,20 @@
 		logcommand(si, CMDLOG_ADMIN, "FLAGS: \2%s\2 (oper override)", mc->name);
 	else
 		logcommand(si, CMDLOG_GET, "FLAGS: \2%s\2", mc->name);
+}
+
+static void check_registration_keywords(hook_user_register_check_t *hdata)
+{
+	if (hdata->approved || !anope_flags_compat)
+	{
+		return;
+	}
+
+	if (!strcasecmp(hdata->account, "LIST") || !strcasecmp(hdata->account, "CLEAR") || !strcasecmp(hdata->account, "MODIFY"))
+	{
+		command_fail(hdata->si, fault_badparams, "The nick \2%s\2 is reserved and cannot be registered.", hdata->account);
+		hdata->approved = 1;
+	}
 }
 
 /* FLAGS <channel> [user] [flags] */
@@ -218,14 +249,14 @@
 	 *
 	 *   --nenolod
 	 */
-	else if (!strcasecmp(target, "LIST") && myentity_find_ext(target) == NULL)
+	else if (anope_flags_compat && !strcasecmp(target, "LIST") && myentity_find_ext(target) == NULL)
 	{
 		do_list(si, mc, 0);
 		free(target);
 
 		return;
 	}
-	else if (!strcasecmp(target, "CLEAR") && myentity_find_ext(target) == NULL)
+	else if (anope_flags_compat && !strcasecmp(target, "CLEAR") && myentity_find_ext(target) == NULL)
 	{
 		free(target);
 
@@ -251,7 +282,7 @@
 		command_success_nodata(si, _("Cleared flags in \2%s\2."), mc->name);
 		return;
 	}
-	else if (!strcasecmp(target, "MODIFY") && myentity_find_ext(target) == NULL)
+	else if (anope_flags_compat && !strcasecmp(target, "MODIFY") && myentity_find_ext(target) == NULL)
 	{
 		free(target);
 
```
