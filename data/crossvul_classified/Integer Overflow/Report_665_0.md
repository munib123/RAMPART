# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 665_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `665_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 2362-2402 of the vulnerable file.

			path_length = path_end - path_ptr;
		}

		entry_size = index_entry_size(path_length, 0, entry.flags);
		entry.path = (char *)path_ptr;
	} else {
		size_t varint_len, last_len, prefix_len, suffix_len, path_len;
		uintmax_t strip_len;

		strip_len = git_decode_varint((const unsigned char *)path_ptr, &varint_len);
		last_len = strlen(last);

		if (varint_len == 0 || last_len < strip_len)
			return index_error_invalid("incorrect prefix length");

		prefix_len = last_len - strip_len;
		suffix_len = strlen(path_ptr + varint_len);

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

	if (index_entry_dup(out, index, &entry) < 0) {
		git__free(tmp_path);
		return -1;
	}

	git__free(tmp_path);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2379,6 +2379,10 @@
 
 		GITERR_CHECK_ALLOC_ADD(&path_len, prefix_len, suffix_len);
 		GITERR_CHECK_ALLOC_ADD(&path_len, path_len, 1);
+
+		if (path_len > GIT_PATH_MAX)
+			return index_error_invalid("unreasonable path length");
+
 		tmp_path = git__malloc(path_len);
 		GITERR_CHECK_ALLOC(tmp_path);
 
```
