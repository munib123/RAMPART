# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1475_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1475_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1319-1359 of the vulnerable file.

	tv.tv_sec = 1;
	tv.tv_usec = 0;
	ret = select(cpipe[0]+1, &s, NULL, NULL, &tv);
	if (ret <= 0)
		goto again;
	ret = read(cpipe[0], &v, 1);
	if (ret != sizeof(char) || v != '1') {
		goto again;
	}

	if (!wait_for_pid(cpid))
		_exit(1);
	_exit(0);

again:
	kill(cpid, SIGKILL);
	wait_for_pid(cpid);
	goto loop;
}

static bool do_write_pids(pid_t tpid, const char *contrl, const char *cg, const char *file, const char *buf)
{
	int sock[2] = {-1, -1};
	pid_t qpid, cpid = -1;
	FILE *pids_file = NULL;
	bool answer = false, fail = false;

	pids_file = open_pids_file(contrl, cg);
	if (!pids_file)
		return false;

	/*
	 * write the pids to a socket, have helper in writer's pidns
	 * call movepid for us
	 */
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sock) < 0) {
		perror("socketpair");
		goto out;
	}

	cpid = fork();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1336,7 +1336,95 @@
 	goto loop;
 }
 
-static bool do_write_pids(pid_t tpid, const char *contrl, const char *cg, const char *file, const char *buf)
+/*
+ * Given host @uid, return the uid to which it maps in
+ * @pid's user namespace, or -1 if none.
+ */
+bool hostuid_to_ns(uid_t uid, pid_t pid, uid_t *answer)
+{
+	FILE *f;
+	char line[400];
+
+	sprintf(line, "/proc/%d/uid_map", pid);
+	if ((f = fopen(line, "r")) == NULL) {
+		return false;
+	}
+
+	*answer = convert_id_to_ns(f, uid);
+	fclose(f);
+
+	if (*answer == -1)
+		return false;
+	return true;
+}
+
+/*
+ * get_pid_creds: get the real uid and gid of @pid from
+ * /proc/$$/status
+ * (XXX should we use euid here?)
+ */
+void get_pid_creds(pid_t pid, uid_t *uid, gid_t *gid)
+{
+	char line[400];
+	uid_t u;
+	gid_t g;
+	FILE *f;
+
+	*uid = -1;
+	*gid = -1;
+	sprintf(line, "/proc/%d/status", pid);
+	if ((f = fopen(line, "r")) == NULL) {
+		fprintf(stderr, "Error opening %s: %s\n", line, strerror(errno));
+		return;
+	}
+	while (fgets(line, 400, f)) {
+		if (strncmp(line, "Uid:", 4) == 0) {
+			if (sscanf(line+4, "%u", &u) != 1) {
+				fprintf(stderr, "bad uid line for pid %u\n", pid);
+				fclose(f);
+				return;
+			}
+			*uid = u;
+		} else if (strncmp(line, "Gid:", 4) == 0) {
+			if (sscanf(line+4, "%u", &g) != 1) {
+				fprintf(stderr, "bad gid line for pid %u\n", pid);
+				fclose(f);
+				return;
+			}
+			*gid = g;
+		}
+	}
+	fclose(f);
+}
+
+/*
+ * May the requestor @r move victim @v to a new cgroup?
+ * This is allowed if
+ *   . they are the same task
+ *   . they are ownedy by the same uid
+ *   . @r is root on the host, or
+ *   . @v's uid is mapped into @r's where @r is root.
+ */
+bool may_move_pid(pid_t r, uid_t r_uid, pid_t v)
+{
+	uid_t v_uid, tmpuid;
+	gid_t v_gid;
+
+	if (r == v)
+		return true;
+	if (r_uid == 0)
+		return true;
+	get_pid_creds(v, &v_uid, &v_gid);
+	if (r_uid == v_uid)
+		return true;
+	if (hostuid_to_ns(r_uid, r, &tmpuid) && tmpuid == 0
+			&& hostuid_to_ns(v_uid, r, &tmpuid))
+		return true;
+	return false;
+}
+
+static bool do_write_pids(pid_t tpid, uid_t tuid, const char *contrl, const char *cg,
+		const char *file, const char *buf)
 {
 	int sock[2] = {-1, -1};
 	pid_t qpid, cpid = -1;
@@ -1378,6 +1466,10 @@
 
 		if (recv_creds(sock[0], &cred, &v)) {
 			if (v == '0') {
+				if (!may_move_pid(tpid, tuid, cred.pid)) {
+					fail = true;
+					break;
+				}
 				if (fprintf(pids_file, "%d", (int) cred.pid) < 0)
 					fail = true;
 			}
@@ -1450,7 +1542,7 @@
 			strcmp(f->file, "/cgroup.procs") == 0 ||
 			strcmp(f->file, "cgroup.procs") == 0)
 		// special case - we have to translate the pids
-		r = do_write_pids(fc->pid, f->controller, f->cgroup, f->file, localbuf);
+		r = do_write_pids(fc->pid, fc->uid, f->controller, f->cgroup, f->file, localbuf);
 	else
 		r = cgfs_set_value(f->controller, f->cgroup, f->file, localbuf);
 
```
