# CrossVul Fix Pair: Access of Uninitialized Pointer in c
**Pair ID:** 250_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-824
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `250_0`)

## Vulnerability Information & PoC

## Description
Access of Uninitialized Pointer - If the pointer contains an uninitialized value, then the value might not point to a valid memory location.

## Vulnerable Code
```c
Lines 184-224 of the vulnerable file.

 * fetch_uidl - parse UIDL
 * @param line String to parse
 * @param data Mailbox Context
 * @retval  0 Success
 * @retval -1 Failure
 */
static int fetch_uidl(char *line, void *data)
{
  int i, index;
  struct Context *ctx = (struct Context *) data;
  struct PopData *pop_data = (struct PopData *) ctx->data;
  char *endp = NULL;

  errno = 0;
  index = strtol(line, &endp, 10);
  if (errno)
    return -1;
  while (*endp == ' ')
    endp++;
  memmove(line, endp, strlen(endp) + 1);

  for (i = 0; i < ctx->msgcount; i++)
    if (mutt_str_strcmp(line, ctx->hdrs[i]->data) == 0)
      break;

  if (i == ctx->msgcount)
  {
    mutt_debug(1, "new header %d %s\n", index, line);

    if (i >= ctx->hdrmax)
      mx_alloc_memory(ctx);

    ctx->msgcount++;
    ctx->hdrs[i] = mutt_header_new();
    ctx->hdrs[i]->data = mutt_str_strdup(line);
  }
  else if (ctx->hdrs[i]->index != index - 1)
    pop_data->clear_cache = true;

  ctx->hdrs[i]->refno = index;
  ctx->hdrs[i]->index = index - 1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -202,6 +202,10 @@
     endp++;
   memmove(line, endp, strlen(endp) + 1);
 
+  /* uid must be at least be 1 byte */
+  if (strlen(line) == 0)
+    return -1;
+
   for (i = 0; i < ctx->msgcount; i++)
     if (mutt_str_strcmp(line, ctx->hdrs[i]->data) == 0)
       break;
```
