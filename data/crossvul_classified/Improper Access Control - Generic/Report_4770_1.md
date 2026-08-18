# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 4770_1
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4770_1`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 151-191 of the vulnerable file.


static int  _abort_step(uint32_t job_id, uint32_t step_id);
static char **_build_env(job_env_t *job_env);
static void _delay_rpc(int host_inx, int host_cnt, int usec_per_rpc);
static void _destroy_env(char **env);
static bool _is_batch_job_finished(uint32_t job_id);
static void _job_limits_free(void *x);
static int  _job_limits_match(void *x, void *key);
static bool _job_still_running(uint32_t job_id);
static int  _kill_all_active_steps(uint32_t jobid, int sig, bool batch);
static void _launch_complete_add(uint32_t job_id);
static void _launch_complete_log(char *type, uint32_t job_id);
static void _launch_complete_rm(uint32_t job_id);
static void _launch_complete_wait(uint32_t job_id);
static int  _launch_job_fail(uint32_t job_id, uint32_t slurm_rc);
static bool _launch_job_test(uint32_t job_id);
static void _note_batch_job_finished(uint32_t job_id);
static int  _prolog_is_running (uint32_t jobid);
static int  _step_limits_match(void *x, void *key);
static int  _terminate_all_steps(uint32_t jobid, bool batch);
static void _rpc_launch_tasks(slurm_msg_t *);
static void _rpc_abort_job(slurm_msg_t *);
static void _rpc_batch_job(slurm_msg_t *msg, bool new_msg);
static void _rpc_prolog(slurm_msg_t *msg);
static void _rpc_job_notify(slurm_msg_t *);
static void _rpc_signal_tasks(slurm_msg_t *);
static void _rpc_checkpoint_tasks(slurm_msg_t *);
static void _rpc_complete_batch(slurm_msg_t *);
static void _rpc_terminate_tasks(slurm_msg_t *);
static void _rpc_timelimit(slurm_msg_t *);
static void _rpc_reattach_tasks(slurm_msg_t *);
static void _rpc_signal_job(slurm_msg_t *);
static void _rpc_suspend_job(slurm_msg_t *msg);
static void _rpc_terminate_job(slurm_msg_t *);
static void _rpc_update_time(slurm_msg_t *);
static void _rpc_shutdown(slurm_msg_t *msg);
static void _rpc_reconfig(slurm_msg_t *msg);
static void _rpc_reboot(slurm_msg_t *msg);
static void _rpc_pid2jid(slurm_msg_t *msg);
static int  _rpc_file_bcast(slurm_msg_t *msg);
static void _file_bcast_cleanup(void);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -168,6 +168,7 @@
 static int  _prolog_is_running (uint32_t jobid);
 static int  _step_limits_match(void *x, void *key);
 static int  _terminate_all_steps(uint32_t jobid, bool batch);
+static int  _receive_fd(int socket);
 static void _rpc_launch_tasks(slurm_msg_t *);
 static void _rpc_abort_job(slurm_msg_t *);
 static void _rpc_batch_job(slurm_msg_t *msg, bool new_msg);
@@ -214,6 +215,7 @@
 static int  _waiter_init (uint32_t jobid);
 static int  _waiter_complete (uint32_t jobid);
 
+static void _send_back_fd(int socket, int fd);
 static bool _steps_completed_now(uint32_t jobid);
 static int  _valid_sbcast_cred(file_bcast_msg_t *req, uid_t req_uid,
 			       uint16_t block_no, uint32_t *job_id);
@@ -1383,6 +1385,111 @@
 		send_registration_msg(errnum, false);
 }
 
+/*
+ * Open file based upon permissions of a different user
+ * IN path_name - name of file to open
+ * IN uid - User ID to use for file access check
+ * IN gid - Group ID to use for file access check
+ * RET -1 on error, file descriptor otherwise
+ */
+static int _open_as_other(char *path_name, batch_job_launch_msg_t *req)
+{
+	pid_t child;
+	gids_t *gids;
+	int pipe[2];
+	int fd = -1, rc = 0;
+
+	if (!(gids = _gids_cache_lookup(req->user_name, req->gid))) {
+		error("%s: gids_cache_lookup for %s failed",
+		      __func__, req->user_name);
+		return -1;
+	}
+
+	if ((rc = container_g_create(req->job_id))) {
+		error("%s: container_g_create(%u): %m", __func__, req->job_id);
+		_dealloc_gids(gids);
+		return -1;
+	}
+
+	/* child process will setuid to the user, register the process
+	 * with the container, and open the file for us. */
+	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pipe) != 0) {
+		error("%s: Failed to open pipe: %m", __func__);
+		_dealloc_gids(gids);
+		return -1;
+	}
+
+	child = fork();
+	if (child == -1) {
+		error("%s: fork failure", __func__);
+		_dealloc_gids(gids);
+		close(pipe[0]);
+		close(pipe[1]);
+		return -1;
+	} else if (child > 0) {
+		close(pipe[0]);
+		(void) waitpid(child, &rc, 0);
+		_dealloc_gids(gids);
+		if (WIFEXITED(rc) && (WEXITSTATUS(rc) == 0))
+			fd = _receive_fd(pipe[1]);
+		close(pipe[1]);
+		return fd;
+	}
+
+	/* child process below here */
+
+	close(pipe[1]);
+
+	/* container_g_add_pid needs to be called in the
+	 * forked process part of the fork to avoid a race
+	 * condition where if this process makes a file or
+	 * detacts itself from a child before we add the pid
+	 * to the container in the parent of the fork. */
+	if (container_g_add_pid(req->job_id, getpid(), req->uid)) {
+		error("%s container_g_add_pid(%u): %m", __func__, req->job_id);
+		exit(SLURM_ERROR);
+	}
+
+	/* The child actually performs the I/O and exits with
+	 * a return code, do not return! */
+
+	/*********************************************************************\
+	 * NOTE: It would be best to do an exec() immediately after the fork()
+	 * in order to help prevent a possible deadlock in the child process
+	 * due to locks being set at the time of the fork and being freed by
+	 * the parent process, but not freed by the child process. Performing
+	 * the work inline is done for simplicity. Note that the logging
+	 * performed by error() should be safe due to the use of
+	 * atfork_install_handlers() as defined in src/common/log.c.
+	 * Change the code below with caution.
+	\*********************************************************************/
+
+	if (setgroups(gids->ngids, gids->gids) < 0) {
+		error("%s: uid: %u setgroups failed: %m", __func__, req->uid);
+		exit(errno);
+	}
+	_dealloc_gids(gids);
+
+	if (setgid(req->gid) < 0) {
+		error("%s: uid:%u setgid(%u): %m", __func__, req->uid,req->gid);
+		exit(errno);
+	}
+	if (setuid(req->uid) < 0) {
+		error("%s: getuid(%u): %m", __func__, req->uid);
+		exit(errno);
+	}
+
+	fd = open(path_name, (O_CREAT|O_APPEND|O_WRONLY), 0644);
+	if (fd == -1) {
+		error("%s: uid:%u can't open `%s`: %m",
+		      __func__, req->uid, path_name);
+		exit(errno);
+	}
+	_send_back_fd(pipe[0], fd);
+	close(fd);
+	exit(SLURM_SUCCESS);
+}
+
 static void
 _prolog_error(batch_job_launch_msg_t *req, int rc)
 {
@@ -1415,10 +1522,8 @@
 			req->work_dir, err_name_ptr);
 	else
 		snprintf(path_name, MAXPATHLEN, "/%s", err_name_ptr);
-
-	if ((fd = open(path_name, (O_CREAT|O_APPEND|O_WRONLY), 0644)) == -1) {
-		error("Unable to open %s: %s", path_name,
-		      slurm_strerror(errno));
+	if ((fd = _open_as_other(path_name, req)) == -1) {
+		error("Unable to open %s: Permission denied", path_name);
 		return;
 	}
 	snprintf(err_name, sizeof(err_name),
```
