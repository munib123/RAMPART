# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 389_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `389_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 8935-8975 of the vulnerable file.

static enum ofperr
parse_group_prop_ntr_selection_method(struct ofpbuf *payload,
                                      enum ofp11_group_type group_type,
                                      enum ofp15_group_mod_command group_cmd,
                                      struct ofputil_group_props *gp)
{
    struct ntr_group_prop_selection_method *prop = payload->data;
    size_t fields_len, method_len;
    enum ofperr error;

    switch (group_type) {
    case OFPGT11_SELECT:
        break;
    case OFPGT11_ALL:
    case OFPGT11_INDIRECT:
    case OFPGT11_FF:
        OFPPROP_LOG(&bad_ofmsg_rl, false, "ntr selection method property is "
                    "only allowed for select groups");
        return OFPERR_OFPBPC_BAD_VALUE;
    default:
        OVS_NOT_REACHED();
    }

    switch (group_cmd) {
    case OFPGC15_ADD:
    case OFPGC15_MODIFY:
    case OFPGC15_ADD_OR_MOD:
        break;
    case OFPGC15_DELETE:
    case OFPGC15_INSERT_BUCKET:
    case OFPGC15_REMOVE_BUCKET:
        OFPPROP_LOG(&bad_ofmsg_rl, false, "ntr selection method property is "
                    "only allowed for add and delete group modifications");
        return OFPERR_OFPBPC_BAD_VALUE;
    default:
        OVS_NOT_REACHED();
    }

    if (payload->size < sizeof *prop) {
        OFPPROP_LOG(&bad_ofmsg_rl, false, "ntr selection method property "
                    "length %u is not valid", payload->size);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -8952,7 +8952,7 @@
                     "only allowed for select groups");
         return OFPERR_OFPBPC_BAD_VALUE;
     default:
-        OVS_NOT_REACHED();
+        return OFPERR_OFPGMFC_BAD_TYPE;
     }
 
     switch (group_cmd) {
@@ -8967,7 +8967,7 @@
                     "only allowed for add and delete group modifications");
         return OFPERR_OFPBPC_BAD_VALUE;
     default:
-        OVS_NOT_REACHED();
+        return OFPERR_OFPGMFC_BAD_COMMAND;
     }
 
     if (payload->size < sizeof *prop) {
```
