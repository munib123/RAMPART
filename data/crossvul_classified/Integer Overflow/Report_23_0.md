# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 23_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `23_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 3232-3272 of the vulnerable file.

static inline int make_ascii_get_suffix(char *suffix, item *it, bool return_cas) {
    char *p;
    if (!settings.inline_ascii_response) {
        *suffix = ' ';
        p = itoa_u32(*((uint32_t *) ITEM_suffix(it)), suffix+1);
        *p = ' ';
        p = itoa_u32(it->nbytes-2, p+1);
    } else {
        p = suffix;
    }
    if (return_cas) {
        *p = ' ';
        p = itoa_u64(ITEM_get_cas(it), p+1);
    }
    *p = '\r';
    *(p+1) = '\n';
    *(p+2) = '\0';
    return (p - suffix) + 2;
}

/* ntokens is overwritten here... shrug.. */
static inline void process_get_command(conn *c, token_t *tokens, size_t ntokens, bool return_cas) {
    char *key;
    size_t nkey;
    int i = 0;
    item *it;
    token_t *key_token = &tokens[KEY_TOKEN];
    char *suffix;
    assert(c != NULL);

    do {
        while(key_token->length != 0) {

            key = key_token->value;
            nkey = key_token->length;

            if(nkey > KEY_MAX_LENGTH) {
                out_string(c, "CLIENT_ERROR bad command line format");
                while (i-- > 0) {
                    item_remove(*(c->ilist + i));
                }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3249,6 +3249,16 @@
     return (p - suffix) + 2;
 }
 
+#define IT_REFCOUNT_LIMIT 60000
+static inline item* limited_get(char *key, size_t nkey, conn *c) {
+    item *it = item_get(key, nkey, c, DO_UPDATE);
+    if (it && it->refcount > IT_REFCOUNT_LIMIT) {
+        item_remove(it);
+        it = NULL;
+    }
+    return it;
+}
+
 /* ntokens is overwritten here... shrug.. */
 static inline void process_get_command(conn *c, token_t *tokens, size_t ntokens, bool return_cas) {
     char *key;
@@ -3273,7 +3283,7 @@
                 return;
             }
 
-            it = item_get(key, nkey, c, DO_UPDATE);
+            it = limited_get(key, nkey, c);
             if (settings.detail_enabled) {
                 stats_prefix_record_get(key, nkey, NULL != it);
             }
```
