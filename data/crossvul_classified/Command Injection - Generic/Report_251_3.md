# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in c
**Pair ID:** 251_3
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `251_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```c
Lines 311-348 of the vulnerable file.

/* util.c */
#ifdef USE_HCACHE
header_cache_t *imap_hcache_open(struct ImapData *idata, const char *path);
void imap_hcache_close(struct ImapData *idata);
struct Header *imap_hcache_get(struct ImapData *idata, unsigned int uid);
int imap_hcache_put(struct ImapData *idata, struct Header *h);
int imap_hcache_del(struct ImapData *idata, unsigned int uid);
#endif

int imap_continue(const char *msg, const char *resp);
void imap_error(const char *where, const char *msg);
struct ImapData *imap_new_idata(void);
void imap_free_idata(struct ImapData **idata);
char *imap_fix_path(struct ImapData *idata, const char *mailbox, char *path, size_t plen);
void imap_cachepath(struct ImapData *idata, const char *mailbox, char *dest, size_t dlen);
int imap_get_literal_count(const char *buf, unsigned int *bytes);
char *imap_get_qualifier(char *buf);
int imap_mxcmp(const char *mx1, const char *mx2);
char *imap_next_word(char *s);
void imap_qualify_path(char *dest, size_t len, struct ImapMbox *mx, char *path);
void imap_quote_string(char *dest, size_t dlen, const char *src);
void imap_unquote_string(char *s);
void imap_munge_mbox_name(struct ImapData *idata, char *dest, size_t dlen, const char *src);
void imap_unmunge_mbox_name(struct ImapData *idata, char *s);
int imap_account_match(const struct Account *a1, const struct Account *a2);
void imap_get_parent(char *output, const char *mbox, size_t olen, char delim);

/* utf7.c */
void imap_utf_encode(struct ImapData *idata, char **s);
void imap_utf_decode(struct ImapData *idata, char **s);
void imap_allow_reopen(struct Context *ctx);
void imap_disallow_reopen(struct Context *ctx);

#ifdef USE_HCACHE
#define imap_hcache_keylen mutt_str_strlen
#endif /* USE_HCACHE */

#endif /* _IMAP_PRIVATE_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -328,7 +328,7 @@
 int imap_mxcmp(const char *mx1, const char *mx2);
 char *imap_next_word(char *s);
 void imap_qualify_path(char *dest, size_t len, struct ImapMbox *mx, char *path);
-void imap_quote_string(char *dest, size_t dlen, const char *src);
+void imap_quote_string(char *dest, size_t dlen, const char *src, bool quote_backtick);
 void imap_unquote_string(char *s);
 void imap_munge_mbox_name(struct ImapData *idata, char *dest, size_t dlen, const char *src);
 void imap_unmunge_mbox_name(struct ImapData *idata, char *s);
```
