# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 436_1
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `436_1`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 43-83 of the vulnerable file.

create_pid_dir(void)
{
	if (mkdir(pid_directory, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) && errno != EEXIST) {
		log_message(LOG_INFO, "Unable to create directory %s", pid_directory);
		return;
	}
}

void
remove_pid_dir(void)
{
	if (rmdir(pid_directory) && errno != ENOTEMPTY && errno != EBUSY)
		log_message(LOG_INFO, "unlink of %s failed - error (%d) '%s'", pid_directory, errno, strerror(errno));
}

/* Create the running daemon pidfile */
int
pidfile_write(const char *pid_file, int pid)
{
	FILE *pidfile = NULL;
	int pidfd = creat(pid_file, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (pidfd != -1) pidfile = fdopen(pidfd, "w");

	if (!pidfile) {
		log_message(LOG_INFO, "pidfile_write : Cannot open %s pidfile",
		       pid_file);
		return 0;
	}
	fprintf(pidfile, "%d\n", pid);
	fclose(pidfile);
	return 1;
}

/* Remove the running daemon pidfile */
void
pidfile_rm(const char *pid_file)
{
	unlink(pid_file);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,7 +60,7 @@
 pidfile_write(const char *pid_file, int pid)
 {
 	FILE *pidfile = NULL;
-	int pidfd = creat(pid_file, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
+	int pidfd = open(pid_file, O_NOFOLLOW | O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
 
 	if (pidfd != -1) pidfile = fdopen(pidfd, "w");
 
```
