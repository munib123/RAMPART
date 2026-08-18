# CrossVul Fix Pair: Improper Initialization in c
**Pair ID:** 2629_2
**Vulnerability Class:** Improper Initialization
**CWE:** CWE-665
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2629_2`)

## Vulnerability Information & PoC

## Description
Improper Initialization - This can have security implications when the associated resource is expected to have certain properties or values, such as a variable that determines whether a user has been authenticated or not.

## Vulnerable Code
```c
Lines 575-615 of the vulnerable file.

			/* reset program variables */
			reset_variables();
			timing_point("Variables reset\n");

			/* get PID */
			nagios_pid = (int)getpid();

			/* read in the configuration files (main and resource config files) */
			result = read_main_config_file(config_file);
			if (result != OK) {
				logit(NSLOG_CONFIG_ERROR, TRUE, "Error: Failed to process config file '%s'. Aborting\n", config_file);
				exit(EXIT_FAILURE);
				}
			timing_point("Main config file read\n");

			/* NOTE 11/06/07 EG moved to after we read config files, as user may have overridden timezone offset */
			/* get program (re)start time and save as macro */
			program_start = time(NULL);
			my_free(mac->x[MACRO_PROCESSSTARTTIME]);
			asprintf(&mac->x[MACRO_PROCESSSTARTTIME], "%llu", (unsigned long long)program_start);

			/* drop privileges */
			if(drop_privileges(nagios_user, nagios_group) == ERROR) {

				logit(NSLOG_PROCESS_INFO | NSLOG_RUNTIME_ERROR | NSLOG_CONFIG_ERROR, TRUE, "Failed to drop privileges.  Aborting.");

				cleanup();
				exit(ERROR);
				}

			if (test_path_access(nagios_binary_path, X_OK)) {
				logit(NSLOG_RUNTIME_ERROR, TRUE, "Error: failed to access() %s: %s\n", nagios_binary_path, strerror(errno));
				logit(NSLOG_RUNTIME_ERROR, TRUE, "Error: Spawning workers will be impossible. Aborting.\n");
				exit(EXIT_FAILURE);
				}

			if (test_configured_paths() == ERROR) {
				/* error has already been logged */
				exit(EXIT_FAILURE);
				}
			/* enter daemon mode (unless we're restarting...) */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -592,26 +592,7 @@
 			program_start = time(NULL);
 			my_free(mac->x[MACRO_PROCESSSTARTTIME]);
 			asprintf(&mac->x[MACRO_PROCESSSTARTTIME], "%llu", (unsigned long long)program_start);
-
-			/* drop privileges */
-			if(drop_privileges(nagios_user, nagios_group) == ERROR) {
-
-				logit(NSLOG_PROCESS_INFO | NSLOG_RUNTIME_ERROR | NSLOG_CONFIG_ERROR, TRUE, "Failed to drop privileges.  Aborting.");
-
-				cleanup();
-				exit(ERROR);
-				}
-
-			if (test_path_access(nagios_binary_path, X_OK)) {
-				logit(NSLOG_RUNTIME_ERROR, TRUE, "Error: failed to access() %s: %s\n", nagios_binary_path, strerror(errno));
-				logit(NSLOG_RUNTIME_ERROR, TRUE, "Error: Spawning workers will be impossible. Aborting.\n");
-				exit(EXIT_FAILURE);
-				}
-
-			if (test_configured_paths() == ERROR) {
-				/* error has already been logged */
-				exit(EXIT_FAILURE);
-				}
+			
 			/* enter daemon mode (unless we're restarting...) */
 			if(daemon_mode == TRUE && sigrestart == FALSE) {
 
@@ -626,6 +607,26 @@
 
 				/* get new PID */
 				nagios_pid = (int)getpid();
+				}
+
+			/* drop privileges */
+			if(drop_privileges(nagios_user, nagios_group) == ERROR) {
+
+				logit(NSLOG_PROCESS_INFO | NSLOG_RUNTIME_ERROR | NSLOG_CONFIG_ERROR, TRUE, "Failed to drop privileges.  Aborting.");
+
+				cleanup();
+				exit(ERROR);
+				}
+
+			if (test_path_access(nagios_binary_path, X_OK)) {
+				logit(NSLOG_RUNTIME_ERROR, TRUE, "Error: failed to access() %s: %s\n", nagios_binary_path, strerror(errno));
+				logit(NSLOG_RUNTIME_ERROR, TRUE, "Error: Spawning workers will be impossible. Aborting.\n");
+				exit(EXIT_FAILURE);
+				}
+
+			if (test_configured_paths() == ERROR) {
+				/* error has already been logged */
+				exit(EXIT_FAILURE);
 				}
 
 			/* this must be logged after we read config data, as user may have changed location of main log file */
```
