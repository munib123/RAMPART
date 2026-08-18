# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 3514_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3514_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 226-266 of the vulnerable file.


	if (!allrouters_ok) {
		flog(LOG_WARNING, "resetting ipv6-allrouters membership on %s", iface->Name);
		setup_allrouters_membership(iface);
	}

	return(0);
}

/* note: also called from the root context */
int
set_interface_var(const char *iface,
		  const char *var, const char *name,
		  uint32_t val)
{
	FILE *fp;
	char spath[64+IFNAMSIZ];	/* XXX: magic constant */
	if (snprintf(spath, sizeof(spath), var, iface) >= sizeof(spath))
		return -1;

	if (access(spath, F_OK) != 0)
		return -1;

	fp = fopen(spath, "w");
	if (!fp) {
		if (name)
			flog(LOG_ERR, "failed to set %s (%u) for %s: %s",
			     name, val, iface, strerror(errno));
		return -1;
	}
	fprintf(fp, "%u", val);
	fclose(fp);

	return 0;
}

int
set_interface_linkmtu(const char *iface, uint32_t mtu)
{
	if (privsep_enabled())
		return privsep_interface_linkmtu(iface, mtu);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -243,6 +243,10 @@
 	if (snprintf(spath, sizeof(spath), var, iface) >= sizeof(spath))
 		return -1;
 
+	/* No path traversal */
+	if (strstr(name, "..") || strchr(name, '/'))
+		return -1;
+
 	if (access(spath, F_OK) != 0)
 		return -1;
 
```
