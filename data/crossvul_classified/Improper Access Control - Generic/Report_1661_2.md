# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1661_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1661_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 356-396 of the vulnerable file.

	len = xasprintf(&gecos, "%s,%s,%s,%s,%s",
			ctl->newf.full_name,
			ctl->newf.office,
			ctl->newf.office_phone,
			ctl->newf.home_phone,
			ctl->newf.other);

	/* remove trailing empty fields (but not subfields of ctl->newf.other) */
	if (!ctl->newf.other) {
		while (len > 0 && gecos[len - 1] == ',')
			len--;
		gecos[len] = 0;
	}

#ifdef HAVE_LIBUSER
	if (set_value_libuser("chfn", ctl->username, ctl->pw->pw_uid,
			LU_GECOS, gecos) < 0) {
#else /* HAVE_LIBUSER */
	/* write the new struct passwd to the passwd file. */
	ctl->pw->pw_gecos = gecos;
	if (setpwnam(ctl->pw) < 0) {
		warn("setpwnam failed");
#endif
		printf(_
		       ("Finger information *NOT* changed.  Try again later.\n"));
		return -1;
	}
	free(gecos);
	printf(_("Finger information changed.\n"));
	return 0;
}

int main(int argc, char **argv)
{
	uid_t uid;
	struct chfn_control ctl = {
		.interactive = 1
	};

	sanitize_env();
	setlocale(LC_ALL, "");	/* both for messages and for iscntrl() below */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -373,7 +373,7 @@
 #else /* HAVE_LIBUSER */
 	/* write the new struct passwd to the passwd file. */
 	ctl->pw->pw_gecos = gecos;
-	if (setpwnam(ctl->pw) < 0) {
+	if (setpwnam(ctl->pw, ".chfn") < 0) {
 		warn("setpwnam failed");
 #endif
 		printf(_
```
