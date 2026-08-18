# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 436_12
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `436_12`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 106-146 of the vulnerable file.

						fprintf(fp, " ");
				fprintf(fp, "\n");
				printnext = true;
			}
		}
	}
}

#ifdef _WITH_STACKTRACE_
void
write_stacktrace(const char *file_name, const char *str)
{
	int fd;
	void *buffer[100];
	int nptrs;
	int i;
	char **strs;

	nptrs = backtrace(buffer, 100);
	if (file_name) {
		fd = open(file_name, O_WRONLY | O_APPEND | O_CREAT, 0644);
		if (str)
			dprintf(fd, "%s\n", str);
		backtrace_symbols_fd(buffer, nptrs, fd);
		if (write(fd, "\n", 1) != 1) {
			/* We don't care, but this stops a warning on Ubuntu */
		}
		close(fd);
	} else {
		if (str)
			log_message(LOG_INFO, "%s", str);
		strs = backtrace_symbols(buffer, nptrs);
		if (strs == NULL) {
			log_message(LOG_INFO, "Unable to get stack backtrace");
			return;
		}

		/* We don't need the call to this function, or the first two entries on the stack */
		for (i = 1; i < nptrs - 2; i++)
			log_message(LOG_INFO, "  %s", strs[i]);
		free(strs);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -123,7 +123,7 @@
 
 	nptrs = backtrace(buffer, 100);
 	if (file_name) {
-		fd = open(file_name, O_WRONLY | O_APPEND | O_CREAT, 0644);
+		fd = open(file_name, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
 		if (str)
 			dprintf(fd, "%s\n", str);
 		backtrace_symbols_fd(buffer, nptrs, fd);
@@ -788,6 +788,47 @@
 	return !strcmp(str1, str2);
 }
 
+/* We need to use O_NOFOLLOW if opening a file for write, so that a non privileged user can't
+ * create a symbolic link from the path to a system file and cause a system file to be overwritten. */
+FILE *fopen_safe(const char *path, const char *mode)
+{
+	int fd;
+	FILE *file;
+	int flags = O_NOFOLLOW | O_CREAT;
+
+	if (mode[0] == 'r')
+		return fopen(path, mode);
+
+	if (mode[0] != 'a' && mode[0] != 'w')
+		return NULL;
+
+	if (mode[1] &&
+	    (mode[1] != '+' || mode[2]))
+		return NULL;
+
+	if (mode[0] == 'w')
+		flags |= O_TRUNC;
+	else
+		flags |= O_APPEND;
+
+	if (mode[1])
+		flags |= O_RDWR;
+	else
+		flags |= O_WRONLY;
+
+	fd = open(path, flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
+	if (fd == -1)
+		return NULL;
+
+	file = fdopen (fd, "w");
+	if (!file) {
+		close(fd);
+		return NULL;
+	}
+
+	return file;
+}
+
 void
 set_std_fd(bool force)
 {
```
