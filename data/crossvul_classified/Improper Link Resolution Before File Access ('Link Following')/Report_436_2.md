# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 436_2
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `436_2`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 553-593 of the vulnerable file.

#if !HAVE_DECL_SOCK_NONBLOCK
	if (set_sock_flags(smtp->fd, F_SETFL, O_NONBLOCK))
		log_message(LOG_INFO, "Unable to set NONBLOCK on smtp_connect socket - %s (%d)", strerror(errno), errno);
#endif

#if !HAVE_DECL_SOCK_CLOEXEC
	if (set_sock_flags(smtp->fd, F_SETFD, FD_CLOEXEC))
		log_message(LOG_INFO, "Unable to set CLOEXEC on smtp_connect socket - %s (%d)", strerror(errno), errno);
#endif

	status = tcp_connect(smtp->fd, &global_data->smtp_server);

	/* Handle connection status code */
	thread_add_event(master, SMTP_FSM[status].send, smtp, smtp->fd);
}

#ifdef _SMTP_ALERT_DEBUG_
static void
smtp_log_to_file(smtp_t *smtp)
{
	FILE *fp = fopen("/tmp/smtp-alert.log", "a");
	time_t now;
	struct tm tm;
	char time_buf[25];
	int time_buf_len;

	time(&now);
	localtime_r(&now, &tm);
	time_buf_len = strftime(time_buf, sizeof time_buf, "%a %b %e %X %Y", &tm);

	fprintf(fp, "%s: %s -> %s\n"
		    "%*sSubject: %s\n"
		    "%*sBody:    %s\n\n",
		    time_buf, global_data->email_from, smtp->email_to,
		    time_buf_len - 7, "", smtp->subject,
		    time_buf_len - 7, "", smtp->body);

	fclose(fp);

	free_smtp_all(smtp);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -570,7 +570,7 @@
 static void
 smtp_log_to_file(smtp_t *smtp)
 {
-	FILE *fp = fopen("/tmp/smtp-alert.log", "a");
+	FILE *fp = fopen_safe("/tmp/smtp-alert.log", "a");
 	time_t now;
 	struct tm tm;
 	char time_buf[25];
```
