# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 4069_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4069_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 1233-1273 of the vulnerable file.

    return notrailer;

  return s;
}

/**
 * imap_exec - Execute a command and wait for the response from the server
 * @param adata Imap Account data
 * @param cmdstr Command to execute
 * @param flags  Flags, see #ImapCmdFlags
 * @retval #IMAP_EXEC_SUCCESS Command successful or queued
 * @retval #IMAP_EXEC_ERROR   Command returned an error
 * @retval #IMAP_EXEC_FATAL   Imap connection failure
 *
 * Also, handle untagged responses.
 */
int imap_exec(struct ImapAccountData *adata, const char *cmdstr, ImapCmdFlags flags)
{
  int rc;

  rc = cmd_start(adata, cmdstr, flags);
  if (rc < 0)
  {
    cmd_handle_fatal(adata);
    return IMAP_EXEC_FATAL;
  }

  if (flags & IMAP_CMD_QUEUE)
    return IMAP_EXEC_SUCCESS;

  if ((flags & IMAP_CMD_POLL) && (C_ImapPollTimeout > 0) &&
      ((mutt_socket_poll(adata->conn, C_ImapPollTimeout)) == 0))
  {
    mutt_error(_("Connection to %s timed out"), adata->conn->account.host);
    cmd_handle_fatal(adata);
    return IMAP_EXEC_FATAL;
  }

  /* Allow interruptions, particularly useful if there are network problems. */
  mutt_sig_allow_interrupt(true);
  do
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1250,6 +1250,13 @@
 {
   int rc;
 
+  if (flags & IMAP_CMD_SINGLE)
+  {
+    // Process any existing commands
+    if (adata->nextcmd != adata->lastcmd)
+      imap_exec(adata, NULL, IMAP_CMD_POLL);
+  }
+
   rc = cmd_start(adata, cmdstr, flags);
   if (rc < 0)
   {
@@ -1273,6 +1280,9 @@
   do
   {
     rc = imap_cmd_step(adata);
+    // The queue is empty, so the single command has been processed
+    if ((flags & IMAP_CMD_SINGLE) && (adata->nextcmd == adata->lastcmd))
+      break;
   } while (rc == IMAP_RES_CONTINUE);
   mutt_sig_allow_interrupt(false);
 
```
