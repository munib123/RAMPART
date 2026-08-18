# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3338_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3338_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 3066-3106 of the vulnerable file.

  * indx = cur_token;

  return MAILIMF_NO_ERROR;
}

/*
group           =       display-name ":" [mailbox-list / CFWS] ";"
                        [CFWS]
*/

static int mailimf_group_parse(const char * message, size_t length,
			       size_t * indx,
			       struct mailimf_group ** result)
{
  size_t cur_token;
  char * display_name;
  struct mailimf_mailbox_list * mailbox_list;
  struct mailimf_group * group;
  int r;
  int res;

  cur_token = * indx;

  mailbox_list = NULL;

  r = mailimf_display_name_parse(message, length, &cur_token, &display_name);
  if (r != MAILIMF_NO_ERROR) {
    res = r;
    goto err;
  }

  r = mailimf_colon_parse(message, length, &cur_token);
  if (r != MAILIMF_NO_ERROR) {
    res = r;
    goto free_display_name;
  }

  r = mailimf_mailbox_list_parse(message, length, &cur_token, &mailbox_list);
  switch (r) {
  case MAILIMF_NO_ERROR:
    break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3083,6 +3083,7 @@
   struct mailimf_group * group;
   int r;
   int res;
+  clist * list;
 
   cur_token = * indx;
 
@@ -3108,6 +3109,17 @@
     r = mailimf_cfws_parse(message, length, &cur_token);
     if ((r != MAILIMF_NO_ERROR) && (r != MAILIMF_ERROR_PARSE)) {
       res = r;
+      goto free_display_name;
+    }
+    list = clist_new();
+    if (list == NULL) {
+      res = MAILIMF_ERROR_MEMORY;
+      goto free_display_name;
+    }
+    mailbox_list = mailimf_mailbox_list_new(list);
+    if (mailbox_list == NULL) {
+      res = MAILIMF_ERROR_MEMORY;
+      clist_free(list);
       goto free_display_name;
     }
     break;
```
