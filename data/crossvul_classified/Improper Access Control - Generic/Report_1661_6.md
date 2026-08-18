# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1661_6
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1661_6`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 118-158 of the vulnerable file.

	(void)setrlimit(RLIMIT_CORE, &rlim);

	/* Turn off signals. */
	(void)signal(SIGALRM, SIG_IGN);
	(void)signal(SIGHUP, SIG_IGN);
	(void)signal(SIGINT, SIG_IGN);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGQUIT, SIG_IGN);
	(void)signal(SIGTERM, SIG_IGN);
	(void)signal(SIGTSTP, SIG_IGN);
	(void)signal(SIGTTOU, SIG_IGN);

	/* Create with exact permissions. */
	(void)umask(0);
}

static FILE * pw_tmpfile(int lockfd)
{
	FILE *fd;
	char *tmpname = NULL;
	char *dir = "/etc";

	if ((fd = xfmkstemp(&tmpname, dir)) == NULL) {
		ulckpwdf();
		err(EXIT_FAILURE, _("can't open temporary file"));
	}

	copyfile(lockfd, fileno(fd));
	tmp_file = tmpname;
	return fd;
}

static void pw_write(void)
{
	char tmp[FILENAMELEN + 4];

	sprintf(tmp, "%s%s", orig_file, ".OLD");
	unlink(tmp);

	if (link(orig_file, tmp))
		warn(_("%s: create a link to %s failed"), orig_file, tmp);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -135,9 +135,8 @@
 {
 	FILE *fd;
 	char *tmpname = NULL;
-	char *dir = "/etc";
-
-	if ((fd = xfmkstemp(&tmpname, dir)) == NULL) {
+
+	if ((fd = xfmkstemp(&tmpname, "/etc", ".vipw")) == NULL) {
 		ulckpwdf();
 		err(EXIT_FAILURE, _("can't open temporary file"));
 	}
```
