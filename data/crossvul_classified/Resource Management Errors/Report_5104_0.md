# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 5104_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5104_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 1073-1113 of the vulnerable file.

	offset = dissect_doserror(
		tvb, offset, pinfo, tree, di, drep, hf_rc, NULL);

	return offset;
}

/* XXX - "name" should be an hf_ value for an FT_STRING. */
static int
dissect_spoolss_uint16uni(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			  proto_tree *tree, guint8 *drep _U_, char **data,
			  int hf_name)
{
	gint len, remaining;
	char *text;

	if (offset % 2)
		offset += 2 - (offset % 2);

	/* Get remaining data in buffer as a string */

	remaining = tvb_captured_length_remaining(tvb, offset);
	if (remaining <= 0) {
		if (data)
			*data = g_strdup("");
		return offset;
	}

	text = tvb_get_string_enc(NULL, tvb, offset, remaining, ENC_UTF_16|ENC_LITTLE_ENDIAN);
	len = (int)strlen(text);

	proto_tree_add_string(tree, hf_name, tvb, offset, len * 2, text);

	if (data)
		*data = text;
	else
		g_free(text);

	return offset + (len + 1) * 2;
}

/*
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1090,7 +1090,7 @@
 
 	/* Get remaining data in buffer as a string */
 
-	remaining = tvb_captured_length_remaining(tvb, offset);
+	remaining = tvb_reported_length_remaining(tvb, offset);
 	if (remaining <= 0) {
 		if (data)
 			*data = g_strdup("");
@@ -6198,9 +6198,10 @@
 		end_offset = tvb_reported_length_remaining(tvb, offset) + 1;
 	}
 
-	while (offset < end_offset)
+	while (offset > 0 && offset < end_offset) {
 		offset = dissect_spoolss_uint16uni(
 			tvb, offset, pinfo, tree, drep, NULL, hf_keybuffer);
+	}
 
 	return offset;
 }
```
