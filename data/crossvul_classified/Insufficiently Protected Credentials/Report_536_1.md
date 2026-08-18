# CrossVul Fix Pair: Credentials Management Errors in c
**Pair ID:** 536_1
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-255
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `536_1`)

## Vulnerability Information & PoC

## Description
Credentials Management Errors

## Vulnerable Code
```c
Lines 139-163 of the vulnerable file.

DEFINE_ANSI_FUNC_UNDERLINE(underline,                  UNDERLINE, NORMAL);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_underline,        HIGHLIGHT_UNDERLINE, HIGHLIGHT);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_red_underline,    HIGHLIGHT_RED_UNDERLINE, HIGHLIGHT_RED);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_green_underline,  HIGHLIGHT_GREEN_UNDERLINE, HIGHLIGHT_GREEN);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_yellow_underline, HIGHLIGHT_YELLOW_UNDERLINE, HIGHLIGHT_YELLOW);
DEFINE_ANSI_FUNC_UNDERLINE(highlight_blue_underline,   HIGHLIGHT_BLUE_UNDERLINE, HIGHLIGHT_BLUE);

int get_ctty_devnr(pid_t pid, dev_t *d);
int get_ctty(pid_t, dev_t *_devnr, char **r);

int getttyname_malloc(int fd, char **r);
int getttyname_harder(int fd, char **r);

int ptsname_malloc(int fd, char **ret);
int ptsname_namespace(int pty, char **ret);

int openpt_in_namespace(pid_t pid, int flags);
int open_terminal_in_namespace(pid_t pid, const char *name, int mode);

int vt_default_utf8(void);
int vt_reset_keyboard(int fd);
int vt_restore(int fd);
int vt_release(int fd, bool restore_vt);

void get_log_colors(int priority, const char **on, const char **off, const char **highlight);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -156,6 +156,7 @@
 int open_terminal_in_namespace(pid_t pid, const char *name, int mode);
 
 int vt_default_utf8(void);
+int vt_verify_kbmode(int fd);
 int vt_reset_keyboard(int fd);
 int vt_restore(int fd);
 int vt_release(int fd, bool restore_vt);
```
