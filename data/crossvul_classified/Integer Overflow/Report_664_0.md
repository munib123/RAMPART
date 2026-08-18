# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 664_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `664_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 2348-2394 of the vulnerable file.

		path_ptr = (const char *) buffer + offsetof(struct entry_short, path);

	if (!compressed) {
		path_length = entry.flags & GIT_IDXENTRY_NAMEMASK;

		/* if this is a very long string, we must find its
		 * real length without overflowing */
		if (path_length == 0xFFF) {
			const char *path_end;

			path_end = memchr(path_ptr, '\0', buffer_size);
			if (path_end == NULL)
				return -1;

			path_length = path_end - path_ptr;
		}

		entry_size = index_entry_size(path_length, 0, entry.flags);
		entry.path = (char *)path_ptr;
	} else {
		size_t varint_len;
		size_t strip_len = git_decode_varint((const unsigned char *)path_ptr,
						     &varint_len);
		size_t last_len = strlen(last);
		size_t prefix_len = last_len - strip_len;
		size_t suffix_len = strlen(path_ptr + varint_len);
		size_t path_len;

		if (varint_len == 0)
			return index_error_invalid("incorrect prefix length");

		GITERR_CHECK_ALLOC_ADD(&path_len, prefix_len, suffix_len);
		GITERR_CHECK_ALLOC_ADD(&path_len, path_len, 1);
		tmp_path = git__malloc(path_len);
		GITERR_CHECK_ALLOC(tmp_path);

		memcpy(tmp_path, last, prefix_len);
		memcpy(tmp_path + prefix_len, path_ptr + varint_len, suffix_len + 1);
		entry_size = index_entry_size(suffix_len, varint_len, entry.flags);
		entry.path = tmp_path;
	}

	if (entry_size == 0)
		return -1;

	if (INDEX_FOOTER_SIZE + entry_size > buffer_size)
		return -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2365,16 +2365,17 @@
 		entry_size = index_entry_size(path_length, 0, entry.flags);
 		entry.path = (char *)path_ptr;
 	} else {
-		size_t varint_len;
-		size_t strip_len = git_decode_varint((const unsigned char *)path_ptr,
-						     &varint_len);
-		size_t last_len = strlen(last);
-		size_t prefix_len = last_len - strip_len;
-		size_t suffix_len = strlen(path_ptr + varint_len);
-		size_t path_len;
-
-		if (varint_len == 0)
+		size_t varint_len, last_len, prefix_len, suffix_len, path_len;
+		uintmax_t strip_len;
+
+		strip_len = git_decode_varint((const unsigned char *)path_ptr, &varint_len);
+		last_len = strlen(last);
+
+		if (varint_len == 0 || last_len < strip_len)
 			return index_error_invalid("incorrect prefix length");
+
+		prefix_len = last_len - strip_len;
+		suffix_len = strlen(path_ptr + varint_len);
 
 		GITERR_CHECK_ALLOC_ADD(&path_len, prefix_len, suffix_len);
 		GITERR_CHECK_ALLOC_ADD(&path_len, path_len, 1);
```
