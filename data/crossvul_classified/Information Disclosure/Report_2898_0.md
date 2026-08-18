# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 2898_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2898_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 704-744 of the vulnerable file.

				return result;
			} else if (startsWith(result, "!> ")) {
				P_DEBUG("[App " << details.pid << " stdout] " << line);
				result.erase(0, sizeof("!> ") - 1);
				return result;
			} else {
				if (details.stderrCapturer != NULL) {
					details.stderrCapturer->appendToBuffer(result);
				}
				LoggingKit::logAppOutput(details.pid, "stdout", line.data(), line.size());
			}
		}
	}

	SpawnPreparationInfo prepareSpawn(const Options &options) {
		TRACE_POINT();
		SpawnPreparationInfo info;
		prepareChroot(info, options);
		info.userSwitching = prepareUserSwitching(options);
		prepareSwitchingWorkingDirectory(info, options);
		inferApplicationInfo(info);
		return info;
	}

	void prepareChroot(SpawnPreparationInfo &info, const Options &options) {
		TRACE_POINT();
		info.appRoot = absolutizePath(options.appRoot);
		if (options.preexecChroot.empty()) {
			info.chrootDir = "/";
		} else {
			info.chrootDir = absolutizePath(options.preexecChroot);
		}
		if (info.appRoot != info.chrootDir && startsWith(info.appRoot, info.chrootDir + "/")) {
			SpawnException e("Invalid configuration: '" + info.chrootDir +
				"' has been configured as the chroot jail, but the application " +
				"root directory '" + info.appRoot + "' is not a subdirectory of the " +
				"chroot directory, which it must be.");
			throwSpawnException(e, options);
		}
		if (info.appRoot == info.chrootDir) {
			info.appRootInsideChroot = "/";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -721,7 +721,6 @@
 		prepareChroot(info, options);
 		info.userSwitching = prepareUserSwitching(options);
 		prepareSwitchingWorkingDirectory(info, options);
-		inferApplicationInfo(info);
 		return info;
 	}
 
@@ -775,6 +774,7 @@
 		assert(info.appRootPathsInsideChroot.back() == info.appRootInsideChroot);
 	}
 
+#ifdef false
 	void inferApplicationInfo(SpawnPreparationInfo &info) const {
 		info.codeRevision = readFromRevisionFile(info);
 		if (info.codeRevision.empty()) {
@@ -817,6 +817,7 @@
 			return string();
 		}
 	}
+#endif
 
 	bool shouldLoadShellEnvvars(const Options &options, const SpawnPreparationInfo &preparation) const {
 		if (options.loadShellEnvvars) {
```
