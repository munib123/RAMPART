# CrossVul Fix Pair: Use After Free in c
**Pair ID:** 820_1
**Vulnerability Class:** Use After Free
**CWE:** CWE-416
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `820_1`)

## Vulnerability Information & PoC

## Description
Use After Free - The use of previously-freed memory can have any number of adverse consequences, ranging from the corruption of valid data to the execution of arbitrary code, depending on the instantiation and timi...

## Vulnerable Code
```c
Lines 171-211 of the vulnerable file.

	 */
	if (page_count(page) == 1) {
		lock_page(page);
		return 0;
	}

	return 1;
}
EXPORT_SYMBOL(generic_pipe_buf_steal);

/**
 * generic_pipe_buf_get - get a reference to a &struct pipe_buffer
 * @pipe:	the pipe that the buffer belongs to
 * @buf:	the buffer to get a reference to
 *
 * Description:
 *	This function grabs an extra reference to @buf. It's used in
 *	in the tee() system call, when we duplicate the buffers in one
 *	pipe into another.
 */
void generic_pipe_buf_get(struct pipe_inode_info *pipe, struct pipe_buffer *buf)
{
	get_page(buf->page);
}
EXPORT_SYMBOL(generic_pipe_buf_get);

/**
 * generic_pipe_buf_confirm - verify contents of the pipe buffer
 * @info:	the pipe that the buffer belongs to
 * @buf:	the buffer to confirm
 *
 * Description:
 *	This function does nothing, because the generic pipe code uses
 *	pages that are always good when inserted into the pipe.
 */
int generic_pipe_buf_confirm(struct pipe_inode_info *info,
			     struct pipe_buffer *buf)
{
	return 0;
}
EXPORT_SYMBOL(generic_pipe_buf_confirm);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -188,9 +188,9 @@
  *	in the tee() system call, when we duplicate the buffers in one
  *	pipe into another.
  */
-void generic_pipe_buf_get(struct pipe_inode_info *pipe, struct pipe_buffer *buf)
-{
-	get_page(buf->page);
+bool generic_pipe_buf_get(struct pipe_inode_info *pipe, struct pipe_buffer *buf)
+{
+	return try_get_page(buf->page);
 }
 EXPORT_SYMBOL(generic_pipe_buf_get);
 
```
