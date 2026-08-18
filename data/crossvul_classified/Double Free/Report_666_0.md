# CrossVul Fix Pair: Double Free in c
**Pair ID:** 666_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `666_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 2282-2322 of the vulnerable file.

	return 0;
}

static size_t index_entry_size(size_t path_len, size_t varint_len, uint32_t flags)
{
	if (varint_len) {
		if (flags & GIT_IDXENTRY_EXTENDED)
			return offsetof(struct entry_long, path) + path_len + 1 + varint_len;
		else
			return offsetof(struct entry_short, path) + path_len + 1 + varint_len;
	} else {
#define entry_size(type,len) ((offsetof(type, path) + (len) + 8) & ~7)
		if (flags & GIT_IDXENTRY_EXTENDED)
			return entry_size(struct entry_long, path_len);
		else
			return entry_size(struct entry_short, path_len);
#undef entry_size
	}
}

static size_t read_entry(
	git_index_entry **out,
	git_index *index,
	const void *buffer,
	size_t buffer_size,
	const char *last)
{
	size_t path_length, entry_size;
	const char *path_ptr;
	struct entry_short source;
	git_index_entry entry = {{0}};
	bool compressed = index->version >= INDEX_VERSION_NUMBER_COMP;
	char *tmp_path = NULL;

	if (INDEX_FOOTER_SIZE + minimal_entry_size > buffer_size)
		return 0;

	/* buffer is not guaranteed to be aligned */
	memcpy(&source, buffer, sizeof(struct entry_short));

	entry.ctime.seconds = (git_time_t)ntohl(source.ctime.seconds);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2299,8 +2299,9 @@
 	}
 }
 
-static size_t read_entry(
+static int read_entry(
 	git_index_entry **out,
+	size_t *out_size,
 	git_index *index,
 	const void *buffer,
 	size_t buffer_size,
@@ -2314,7 +2315,7 @@
 	char *tmp_path = NULL;
 
 	if (INDEX_FOOTER_SIZE + minimal_entry_size > buffer_size)
-		return 0;
+		return -1;
 
 	/* buffer is not guaranteed to be aligned */
 	memcpy(&source, buffer, sizeof(struct entry_short));
@@ -2356,7 +2357,7 @@
 
 			path_end = memchr(path_ptr, '\0', buffer_size);
 			if (path_end == NULL)
-				return 0;
+				return -1;
 
 			path_length = path_end - path_ptr;
 		}
@@ -2386,16 +2387,20 @@
 		entry.path = tmp_path;
 	}
 
+	if (entry_size == 0)
+		return -1;
+
 	if (INDEX_FOOTER_SIZE + entry_size > buffer_size)
-		return 0;
+		return -1;
 
 	if (index_entry_dup(out, index, &entry) < 0) {
 		git__free(tmp_path);
-		return 0;
+		return -1;
 	}
 
 	git__free(tmp_path);
-	return entry_size;
+	*out_size = entry_size;
+	return 0;
 }
 
 static int read_header(struct index_header *dest, const void *buffer)
@@ -2499,10 +2504,9 @@
 	/* Parse all the entries */
 	for (i = 0; i < header.entry_count && buffer_size > INDEX_FOOTER_SIZE; ++i) {
 		git_index_entry *entry = NULL;
-		size_t entry_size = read_entry(&entry, index, buffer, buffer_size, last);
-
-		/* 0 bytes read means an object corruption */
-		if (entry_size == 0) {
+		size_t entry_size;
+
+		if ((error = read_entry(&entry, &entry_size, index, buffer, buffer_size, last)) < 0) {
 			error = index_error_invalid("invalid entry");
 			goto done;
 		}
```
