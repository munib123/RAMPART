# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1658_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1658_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 63-108 of the vulnerable file.

char	*stats_drift_file;		/* frequency file name */
static	char *stats_temp_file;		/* temp frequency file name */
static double wander_resid;		/* last frequency update */
double	wander_threshold = 1e-7;	/* initial frequency threshold */

/*
 * Statistics file stuff
 */
#ifndef NTP_VAR
# ifndef SYS_WINNT
#  define NTP_VAR "/var/NTP/"		/* NOTE the trailing '/' */
# else
#  define NTP_VAR "c:\\var\\ntp\\"	/* NOTE the trailing '\\' */
# endif /* SYS_WINNT */
#endif

#ifndef MAXPATHLEN
# define MAXPATHLEN 256
#endif

#ifdef DEBUG_TIMING
static FILEGEN timingstats;
#endif
#ifdef AUTOKEY
static FILEGEN cryptostats;
#endif	/* AUTOKEY */

static	char statsdir[MAXPATHLEN] = NTP_VAR;
static FILEGEN peerstats;
static FILEGEN loopstats;
static FILEGEN clockstats;
static FILEGEN rawstats;
static FILEGEN sysstats;
static FILEGEN protostats;

/*
 * This controls whether stats are written to the fileset. Provided
 * so that ntpdc can turn off stats when the file system fills up. 
 */
int stats_control;

/*
 * Last frequency written to file.
 */
static double prev_drift_comp;		/* last frequency update */

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -80,12 +80,6 @@
 # define MAXPATHLEN 256
 #endif
 
-#ifdef DEBUG_TIMING
-static FILEGEN timingstats;
-#endif
-#ifdef AUTOKEY
-static FILEGEN cryptostats;
-#endif	/* AUTOKEY */
 
 static	char statsdir[MAXPATHLEN] = NTP_VAR;
 static FILEGEN peerstats;
@@ -94,6 +88,8 @@
 static FILEGEN rawstats;
 static FILEGEN sysstats;
 static FILEGEN protostats;
+static FILEGEN cryptostats;
+static FILEGEN timingstats;
 
 /*
  * This controls whether stats are written to the fileset. Provided
@@ -173,12 +169,8 @@
 	filegen_register(statsdir, "rawstats",	  &rawstats);
 	filegen_register(statsdir, "sysstats",	  &sysstats);
 	filegen_register(statsdir, "protostats",  &protostats);
-#ifdef AUTOKEY
 	filegen_register(statsdir, "cryptostats", &cryptostats);
-#endif	/* AUTOKEY */
-#ifdef DEBUG_TIMING
 	filegen_register(statsdir, "timingstats", &timingstats);
-#endif	/* DEBUG_TIMING */
 	/*
 	 * register with libntp ntp_set_tod() to call us back
 	 * when time is stepped.
```
