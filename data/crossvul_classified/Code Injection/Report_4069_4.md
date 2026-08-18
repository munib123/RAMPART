# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 4069_4
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4069_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 56-96 of the vulnerable file.

#define IMAP_RES_CONTINUE  1  ///< `* ...`
#define IMAP_RES_RESPOND   2  ///< `+`
#define IMAP_RES_NEW       3  ///< ImapCommand.state additions

#define SEQ_LEN 16
#define IMAP_MAX_CMDLEN 1024 ///< Maximum length of command lines before they must be split (for lazy servers)

typedef uint8_t ImapOpenFlags;         ///< Flags, e.g. #MUTT_THREAD_COLLAPSE
#define IMAP_OPEN_NO_FLAGS          0  ///< No flags are set
#define IMAP_REOPEN_ALLOW     (1 << 0) ///< Allow re-opening a folder upon expunge
#define IMAP_EXPUNGE_EXPECTED (1 << 1) ///< Messages will be expunged from the server
#define IMAP_EXPUNGE_PENDING  (1 << 2) ///< Messages on the server have been expunged
#define IMAP_NEWMAIL_PENDING  (1 << 3) ///< New mail is waiting on the server
#define IMAP_FLAGS_PENDING    (1 << 4) ///< Flags have changed on the server

typedef uint8_t ImapCmdFlags;          ///< Flags for imap_exec(), e.g. #IMAP_CMD_PASS
#define IMAP_CMD_NO_FLAGS          0   ///< No flags are set
#define IMAP_CMD_PASS        (1 << 0)  ///< Command contains a password. Suppress logging
#define IMAP_CMD_QUEUE       (1 << 1)  ///< Queue a command, do not execute
#define IMAP_CMD_POLL        (1 << 2)  ///< Poll the tcp connection before running the imap command

/**
 * enum ImapExecResult - imap_exec return code
 */
enum ImapExecResult
{
  IMAP_EXEC_SUCCESS = 0, ///< Imap command executed or queued successfully
  IMAP_EXEC_ERROR,       ///< Imap command failure
  IMAP_EXEC_FATAL,       ///< Imap connection failure
};

/* length of "DD-MMM-YYYY HH:MM:SS +ZZzz" (null-terminated) */
#define IMAP_DATELEN 27

/**
 * enum ImapFlags - IMAP server responses
 */
enum ImapFlags
{
  IMAP_FATAL = 1, ///< Unrecoverable error occurred
  IMAP_BYE,       ///< Logged out from server
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -73,6 +73,7 @@
 #define IMAP_CMD_PASS        (1 << 0)  ///< Command contains a password. Suppress logging
 #define IMAP_CMD_QUEUE       (1 << 1)  ///< Queue a command, do not execute
 #define IMAP_CMD_POLL        (1 << 2)  ///< Poll the tcp connection before running the imap command
+#define IMAP_CMD_SINGLE      (1 << 3)  ///< Run a single command
 
 /**
  * enum ImapExecResult - imap_exec return code
```
