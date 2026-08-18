# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 436_8
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `436_8`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 61-101 of the vulnerable file.

		fclose(log_file);
		log_file = NULL;
	}
}

void
open_log_file(const char *name, const char *prog, const char *namespace, const char *instance)
{
	char *file_name;

	if (log_file) {
		fclose(log_file);
		log_file = NULL;
	}

	if (!name)
		return;

	file_name = make_file_name(name, prog, namespace, instance);

	log_file = fopen(file_name, "a");
	if (log_file) {
		int n = fileno(log_file);
		fcntl(n, F_SETFD, FD_CLOEXEC | fcntl(n, F_GETFD));
		fcntl(n, F_SETFL, O_NONBLOCK | fcntl(n, F_GETFL));
	}

	FREE(file_name);
}

void
flush_log_file(void)
{
	if (log_file)
		fflush(log_file);
}

void
vlog_message(const int facility, const char* format, va_list args)
{
#if !HAVE_VSYSLOG
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,7 +78,7 @@
 
 	file_name = make_file_name(name, prog, namespace, instance);
 
-	log_file = fopen(file_name, "a");
+	log_file = fopen_safe(file_name, "a");
 	if (log_file) {
 		int n = fileno(log_file);
 		fcntl(n, F_SETFD, FD_CLOEXEC | fcntl(n, F_GETFD));
```
