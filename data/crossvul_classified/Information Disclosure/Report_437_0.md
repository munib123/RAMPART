# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 437_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `437_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 865-905 of the vulnerable file.

		if (getrlimit(RLIMIT_CORE, &orig_rlim) == -1)
			log_message(LOG_INFO, "Failed to get core file size");
		else if (setrlimit(RLIMIT_CORE, &rlim) == -1)
			log_message(LOG_INFO, "Failed to set core file size");
		else
			set_child_rlimit(RLIMIT_CORE, &orig_rlim);
	}
}

static mode_t
set_umask(const char *optarg)
{
	long umask_long;
	mode_t umask_val;
	char *endptr;

	umask_long = strtoll(optarg, &endptr, 0);

	if (*endptr || umask_long < 0 || umask_long & ~0777L) {
		fprintf(stderr, "Invalid --umask option %s", optarg);
		return;
	}

	umask_val = umask_long & 0777;
	umask(umask_val);

	umask_cmdline = true;

	return umask_val;
}

void
initialise_debug_options(void)
{
#if defined WITH_DEBUG_OPTIONS && !defined _DEBUG_
	char mask = 0;

	if (prog_type == PROG_TYPE_PARENT)
		mask = 1 << PROG_TYPE_PARENT;
#if _WITH_BFD_
	else if (prog_type == PROG_TYPE_BFD)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -882,7 +882,7 @@
 
 	if (*endptr || umask_long < 0 || umask_long & ~0777L) {
 		fprintf(stderr, "Invalid --umask option %s", optarg);
-		return;
+		return 0;
 	}
 
 	umask_val = umask_long & 0777;
```
