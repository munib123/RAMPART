# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2561_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2561_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 37-77 of the vulnerable file.

	nick->next = NULL;

	list = g_hash_table_lookup(channel->nicks, nick->nick);
        if (list == NULL)
		g_hash_table_insert(channel->nicks, nick->nick, nick);
	else {
                /* multiple nicks with same name */
		while (list->next != NULL)
			list = list->next;
		list->next = nick;
	}

	if (nick == channel->ownnick) {
                /* move our own nick to beginning of the nick list.. */
		nicklist_set_own(channel, nick);
	}
}

static void nick_hash_remove(CHANNEL_REC *channel, NICK_REC *nick)
{
	NICK_REC *list;

	list = g_hash_table_lookup(channel->nicks, nick->nick);
	if (list == NULL)
		return;

	if (list == nick || list->next == NULL) {
		g_hash_table_remove(channel->nicks, nick->nick);
		if (list->next != NULL) {
			g_hash_table_insert(channel->nicks, nick->next->nick,
					    nick->next);
		}
	} else {
		while (list->next != nick)
			list = list->next;
		list->next = nick->next;
	}
}

/* Add new nick to list */
void nicklist_insert(CHANNEL_REC *channel, NICK_REC *nick)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -54,22 +54,25 @@
 
 static void nick_hash_remove(CHANNEL_REC *channel, NICK_REC *nick)
 {
-	NICK_REC *list;
+	NICK_REC *list, *newlist;
 
 	list = g_hash_table_lookup(channel->nicks, nick->nick);
 	if (list == NULL)
 		return;
 
-	if (list == nick || list->next == NULL) {
-		g_hash_table_remove(channel->nicks, nick->nick);
-		if (list->next != NULL) {
-			g_hash_table_insert(channel->nicks, nick->next->nick,
-					    nick->next);
-		}
+	if (list == nick) {
+		newlist = nick->next;
 	} else {
+		newlist = list;
 		while (list->next != nick)
 			list = list->next;
 		list->next = nick->next;
+	}
+
+	g_hash_table_remove(channel->nicks, nick->nick);
+	if (newlist != NULL) {
+		g_hash_table_insert(channel->nicks, newlist->nick,
+				    newlist);
 	}
 }
 
```
