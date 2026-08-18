# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 4984_1
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4984_1`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 20-60 of the vulnerable file.

#include <linux/pagemap.h>
#include <linux/audit.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>

#include <asm/uaccess.h>
#include <asm/ioctls.h>

#include "internal.h"

/*
 * The max size that a non-root user is allowed to grow the pipe. Can
 * be set by root in /proc/sys/fs/pipe-max-size
 */
unsigned int pipe_max_size = 1048576;

/*
 * Minimum pipe size, as required by POSIX
 */
unsigned int pipe_min_size = PAGE_SIZE;

/*
 * We use a start+len construction, which provides full use of the 
 * allocated memory.
 * -- Florian Coosmann (FGC)
 * 
 * Reads with count = 0 should always return 0.
 * -- Julian Bradfield 1999-06-07.
 *
 * FIFOs and Pipes now generate SIGIO for both readers and writers.
 * -- Jeremy Elson <jelson@circlemud.org> 2001-08-16
 *
 * pipe_read & write cleanup
 * -- Manfred Spraul <manfred@colorfullife.com> 2002-05-09
 */

static void pipe_lock_nested(struct pipe_inode_info *pipe, int subclass)
{
	if (pipe->files)
		mutex_lock_nested(&pipe->mutex, subclass);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -37,6 +37,12 @@
  * Minimum pipe size, as required by POSIX
  */
 unsigned int pipe_min_size = PAGE_SIZE;
+
+/* Maximum allocatable pages per user. Hard limit is unset by default, soft
+ * matches default values.
+ */
+unsigned long pipe_user_pages_hard;
+unsigned long pipe_user_pages_soft = PIPE_DEF_BUFFERS * INR_OPEN_CUR;
 
 /*
  * We use a start+len construction, which provides full use of the 
@@ -583,20 +589,49 @@
 	return retval;
 }
 
+static void account_pipe_buffers(struct pipe_inode_info *pipe,
+                                 unsigned long old, unsigned long new)
+{
+	atomic_long_add(new - old, &pipe->user->pipe_bufs);
+}
+
+static bool too_many_pipe_buffers_soft(struct user_struct *user)
+{
+	return pipe_user_pages_soft &&
+	       atomic_long_read(&user->pipe_bufs) >= pipe_user_pages_soft;
+}
+
+static bool too_many_pipe_buffers_hard(struct user_struct *user)
+{
+	return pipe_user_pages_hard &&
+	       atomic_long_read(&user->pipe_bufs) >= pipe_user_pages_hard;
+}
+
 struct pipe_inode_info *alloc_pipe_info(void)
 {
 	struct pipe_inode_info *pipe;
 
 	pipe = kzalloc(sizeof(struct pipe_inode_info), GFP_KERNEL);
 	if (pipe) {
-		pipe->bufs = kzalloc(sizeof(struct pipe_buffer) * PIPE_DEF_BUFFERS, GFP_KERNEL);
+		unsigned long pipe_bufs = PIPE_DEF_BUFFERS;
+		struct user_struct *user = get_current_user();
+
+		if (!too_many_pipe_buffers_hard(user)) {
+			if (too_many_pipe_buffers_soft(user))
+				pipe_bufs = 1;
+			pipe->bufs = kzalloc(sizeof(struct pipe_buffer) * pipe_bufs, GFP_KERNEL);
+		}
+
 		if (pipe->bufs) {
 			init_waitqueue_head(&pipe->wait);
 			pipe->r_counter = pipe->w_counter = 1;
-			pipe->buffers = PIPE_DEF_BUFFERS;
+			pipe->buffers = pipe_bufs;
+			pipe->user = user;
+			account_pipe_buffers(pipe, 0, pipe_bufs);
 			mutex_init(&pipe->mutex);
 			return pipe;
 		}
+		free_uid(user);
 		kfree(pipe);
 	}
 
@@ -607,6 +642,8 @@
 {
 	int i;
 
+	account_pipe_buffers(pipe, pipe->buffers, 0);
+	free_uid(pipe->user);
 	for (i = 0; i < pipe->buffers; i++) {
 		struct pipe_buffer *buf = pipe->bufs + i;
 		if (buf->ops)
@@ -998,6 +1035,7 @@
 			memcpy(bufs + head, pipe->bufs, tail * sizeof(struct pipe_buffer));
 	}
 
+	account_pipe_buffers(pipe, pipe->buffers, nr_pages);
 	pipe->curbuf = 0;
 	kfree(pipe->bufs);
 	pipe->bufs = bufs;
@@ -1067,6 +1105,11 @@
 			goto out;
 
 		if (!capable(CAP_SYS_RESOURCE) && size > pipe_max_size) {
+			ret = -EPERM;
+			goto out;
+		} else if ((too_many_pipe_buffers_hard(pipe->user) ||
+			    too_many_pipe_buffers_soft(pipe->user)) &&
+		           !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN)) {
 			ret = -EPERM;
 			goto out;
 		}
```
