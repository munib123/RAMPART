# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 5487_2
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5487_2`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 95-135 of the vulnerable file.


	/* write to main log */
	write_to_log(buffer, data_type, NULL);

	return OK;
	}


/* write something to the log file and syslog facility */
static void write_to_all_logs_with_timestamp(char *buffer, unsigned long data_type, time_t *timestamp) {
	/* write to syslog */
	write_to_syslog(buffer, data_type);

	/* write to main log */
	write_to_log(buffer, data_type, timestamp);
	}


static FILE *open_log_file(void)
{
	if(log_fp) /* keep it open unless we rotate */
		return log_fp;

	log_fp = fopen(log_file, "a+");
	if(log_fp == NULL) {
		if (daemon_mode == FALSE) {
			printf("Warning: Cannot open log file '%s' for writing\n", log_file);
			}
		return NULL;
		}

	(void)fcntl(fileno(log_fp), F_SETFD, FD_CLOEXEC);
	return log_fp;
}

int fix_log_file_owner(uid_t uid, gid_t gid)
{
	int r1 = 0, r2 = 0;

	if (!(log_fp = open_log_file()))
		return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -112,16 +112,38 @@
 
 static FILE *open_log_file(void)
 {
+	int fh;
+	struct stat st;
+
 	if(log_fp) /* keep it open unless we rotate */
 		return log_fp;
 
-	log_fp = fopen(log_file, "a+");
+	if ((fh = open(log_file, O_RDWR|O_APPEND|O_CREAT|O_NOFOLLOW, S_IRUSR|S_IWUSR)) == -1) {
+		if (daemon_mode == FALSE)
+			printf("Warning: Cannot open log file '%s' for writing\n", log_file);
+		return NULL;
+	}
+	log_fp = fdopen(fh, "a+");
 	if(log_fp == NULL) {
-		if (daemon_mode == FALSE) {
+		if (daemon_mode == FALSE)
 			printf("Warning: Cannot open log file '%s' for writing\n", log_file);
-			}
 		return NULL;
 		}
+
+	if ((fstat(fh, &st)) == -1) {
+		log_fp = NULL;
+		close(fh);
+		if (daemon_mode == FALSE)
+			printf("Warning: Cannot fstat log file '%s'\n", log_file);
+		return NULL;
+	}
+	if (st.st_nlink != 1 || (st.st_mode & S_IFMT) != S_IFREG) {
+		log_fp = NULL;
+		close(fh);
+		if (daemon_mode == FALSE)
+			printf("Warning: log file '%s' has an invalid mode\n", log_file);
+		return NULL;
+	}
 
 	(void)fcntl(fileno(log_fp), F_SETFD, FD_CLOEXEC);
 	return log_fp;
@@ -447,7 +469,10 @@
 
 
 /* opens the debug log for writing */
-int open_debug_log(void) {
+int open_debug_log(void)
+{
+	int fh;
+	struct stat st;
 
 	/* don't do anything if we're not actually running... */
 	if(verify_config || test_scheduling == TRUE)
@@ -457,10 +482,23 @@
 	if(debug_level == DEBUGL_NONE)
 		return OK;
 
-	if((debug_file_fp = fopen(debug_file, "a+")) == NULL)
-		return ERROR;
-
-	(void)fcntl(fileno(debug_file_fp), F_SETFD, FD_CLOEXEC);
+	if ((fh = open(debug_file, O_RDWR|O_APPEND|O_CREAT|O_NOFOLLOW, S_IRUSR|S_IWUSR)) == -1)
+		return ERROR;
+	if((debug_file_fp = fdopen(fh, "a+")) == NULL)
+		return ERROR;
+
+	if ((fstat(fh, &st)) == -1) {
+		debug_file_fp = NULL;
+		close(fh);
+		return ERROR;
+	}
+	if (st.st_nlink != 1 || (st.st_mode & S_IFMT) != S_IFREG) {
+		debug_file_fp = NULL;
+		close(fh);
+		return ERROR;
+	}
+
+	(void)fcntl(fh, F_SETFD, FD_CLOEXEC);
 
 	return OK;
 	}
```
