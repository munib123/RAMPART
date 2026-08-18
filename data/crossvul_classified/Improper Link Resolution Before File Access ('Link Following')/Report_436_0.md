# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 436_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `436_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 1382-1422 of the vulnerable file.

				log_file_name = optarg;
			else
				log_file_name = "/tmp/keepalived.log";
			open_log_file(log_file_name, NULL, NULL, NULL);
			break;
		case 'G':
			__set_bit(NO_SYSLOG_BIT, &debug);
			reopen_log = true;
			break;
		case 'u':
			new_umask_val = set_umask(optarg);
			if (umask_cmdline)
				umask_val = new_umask_val;
			break;
		case 't':
			__set_bit(CONFIG_TEST_BIT, &debug);
			__set_bit(DONT_RESPAWN_BIT, &debug);
			__set_bit(DONT_FORK_BIT, &debug);
			__set_bit(NO_SYSLOG_BIT, &debug);
			if (optarg && optarg[0]) {
				int fd = open(optarg, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				if (fd == -1) {
					fprintf(stderr, "Unable to open config-test log file %s\n", optarg);
					exit(EXIT_FAILURE);
				}
				dup2(fd, STDERR_FILENO);
				close(fd);
			}
			break;
		case 'f':
			conf_file = optarg;
			break;
		case 2:		/* --flush-log-file */
			set_flush_log_file();
			break;
#if defined _WITH_VRRP_ && defined _WITH_LVS_
		case 'P':
			__clear_bit(DAEMON_CHECKERS, &daemon_mode);
			break;
		case 'C':
			__clear_bit(DAEMON_VRRP, &daemon_mode);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1399,7 +1399,7 @@
 			__set_bit(DONT_FORK_BIT, &debug);
 			__set_bit(NO_SYSLOG_BIT, &debug);
 			if (optarg && optarg[0]) {
-				int fd = open(optarg, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
+				int fd = open(optarg, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
 				if (fd == -1) {
 					fprintf(stderr, "Unable to open config-test log file %s\n", optarg);
 					exit(EXIT_FAILURE);
```
