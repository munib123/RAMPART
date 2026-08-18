# CrossVul Fix Pair: Incorrect Type Conversion or Cast in c
**Pair ID:** 188_0
**Vulnerability Class:** Type Confusion
**CWE:** CWE-704
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `188_0`)

## Vulnerability Information & PoC

## Description
Incorrect Type Conversion or Cast - The product does not correctly convert an object, resource, or structure from one type to a different type.

## Vulnerable Code
```c
Lines 1559-1599 of the vulnerable file.

 * XGROUP SETID <key> <id or $>
 * XGROUP DELGROUP <key> <groupname>
 * XGROUP DELCONSUMER <key> <groupname> <consumername> */
void xgroupCommand(client *c) {
    const char *help[] = {
"CREATE      <key> <groupname> <id or $>  -- Create a new consumer group.",
"SETID       <key> <groupname> <id or $>  -- Set the current group ID.",
"DELGROUP    <key> <groupname>            -- Remove the specified group.",
"DELCONSUMER <key> <groupname> <consumer> -- Remove the specified conusmer.",
"HELP                                     -- Prints this help.",
NULL
    };
    stream *s = NULL;
    sds grpname = NULL;
    streamCG *cg = NULL;
    char *opt = c->argv[1]->ptr; /* Subcommand name. */

    /* Lookup the key now, this is common for all the subcommands but HELP. */
    if (c->argc >= 4) {
        robj *o = lookupKeyWriteOrReply(c,c->argv[2],shared.nokeyerr);
        if (o == NULL) return;
        s = o->ptr;
        grpname = c->argv[3]->ptr;

        /* Certain subcommands require the group to exist. */
        if ((cg = streamLookupCG(s,grpname)) == NULL &&
            (!strcasecmp(opt,"SETID") ||
             !strcasecmp(opt,"DELCONSUMER")))
        {
            addReplyErrorFormat(c, "-NOGROUP No such consumer group '%s' "
                                   "for key name '%s'",
                                   (char*)grpname, (char*)c->argv[2]->ptr);
            return;
        }
    }

    /* Dispatch the different subcommands. */
    if (!strcasecmp(opt,"CREATE") && c->argc == 5) {
        streamID id;
        if (!strcmp(c->argv[4]->ptr,"$")) {
            id = s->last_id;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1576,7 +1576,7 @@
     /* Lookup the key now, this is common for all the subcommands but HELP. */
     if (c->argc >= 4) {
         robj *o = lookupKeyWriteOrReply(c,c->argv[2],shared.nokeyerr);
-        if (o == NULL) return;
+        if (o == NULL || checkType(c,o,OBJ_STREAM)) return;
         s = o->ptr;
         grpname = c->argv[3]->ptr;
 
```
