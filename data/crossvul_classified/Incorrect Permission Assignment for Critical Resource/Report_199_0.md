# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in cpp
**Pair ID:** 199_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `199_0`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```cpp
Lines 184-224 of the vulnerable file.

				int groups[1024];
				int ngroups = sizeof(groups) / sizeof(int);
			#else
				gid_t groups[1024];
				int ngroups = sizeof(groups) / sizeof(gid_t);
			#endif
			boost::scoped_array<gid_t> gidset;

			int ret = getgrouplist(userInfo->pw_name, gid,
				groups, &ngroups);
			if (ret == -1) {
				int e = errno;
				fprintf(stderr, "ERROR: getgrouplist(%s, %d) failed: %s (errno=%d)\n",
					userInfo->pw_name, (int) gid, strerror(e), e);
				exit(1);
			}

			if (ngroups <= NGROUPS_MAX) {
				setgroupsCalled = true;
				gidset.reset(new gid_t[ngroups]);
				if (setgroups(ngroups, gidset.get()) == -1) {
					int e = errno;
					fprintf(stderr, "ERROR: setgroups(%d, ...) failed: %s (errno=%d)\n",
						ngroups, strerror(e), e);
					exit(1);
				}
			}
		#endif

		if (!setgroupsCalled && initgroups(userInfo->pw_name, gid) == -1) {
			int e = errno;
			fprintf(stderr, "ERROR: initgroups(%s, %d) failed: %s (errno=%d)\n",
				userInfo->pw_name, (int) gid, strerror(e), e);
			exit(1);
		}
	}

	if (setgid(gid) == -1) {
		int e = errno;
		fprintf(stderr, "ERROR: setgid(%d) failed: %s (errno=%d)\n",
			(int) gid, strerror(e), e);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -201,6 +201,9 @@
 			if (ngroups <= NGROUPS_MAX) {
 				setgroupsCalled = true;
 				gidset.reset(new gid_t[ngroups]);
+				for (int i = 0; i < ngroups; i++) {
+					gidset[i] = groups[i];
+				}
 				if (setgroups(ngroups, gidset.get()) == -1) {
 					int e = errno;
 					fprintf(stderr, "ERROR: setgroups(%d, ...) failed: %s (errno=%d)\n",
```
