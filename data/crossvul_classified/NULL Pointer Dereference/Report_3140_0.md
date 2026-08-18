# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 3140_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3140_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 128-168 of the vulnerable file.

		px->xfer = xfer;

		next_ft = NULL;
	}
}

static gboolean prplcb_xfer_new_send_cb(gpointer data, gint fd, b_input_condition cond)
{
	PurpleXfer *xfer = data;
	struct im_connection *ic = purple_ic_by_pa(xfer->account);
	struct prpl_xfer_data *px = xfer->ui_data;
	PurpleBuddy *buddy;
	const char *who;

	buddy = purple_find_buddy(xfer->account, xfer->who);
	who = buddy ? purple_buddy_get_name(buddy) : xfer->who;

	/* TODO(wilmer): After spreading some more const goodness in BitlBee,
	   remove the evil cast below. */
	px->ft = imcb_file_send_start(ic, (char *) who, xfer->filename, xfer->size);
	px->ft->data = px;

	px->ft->accept = prpl_xfer_accept;
	px->ft->canceled = prpl_xfer_canceled;
	px->ft->free = prpl_xfer_free;
	px->ft->write_request = prpl_xfer_write_request;

	return FALSE;
}

gboolean try_write_to_ui(gpointer data, gint fd, b_input_condition cond)
{
	struct file_transfer *ft = data;
	struct prpl_xfer_data *px = ft->data;
	struct stat fs;
	off_t tx_bytes;

	/* If we don't have the file opened yet, there's no data so wait. */
	if (px->fd < 0 || !px->ui_wants_data) {
		return FALSE;
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -145,6 +145,10 @@
 	/* TODO(wilmer): After spreading some more const goodness in BitlBee,
 	   remove the evil cast below. */
 	px->ft = imcb_file_send_start(ic, (char *) who, xfer->filename, xfer->size);
+
+	if (!px->ft) {
+		return FALSE;
+	}
 	px->ft->data = px;
 
 	px->ft->accept = prpl_xfer_accept;
```
