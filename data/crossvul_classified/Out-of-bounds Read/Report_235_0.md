# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 235_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `235_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 345-385 of the vulnerable file.

	struct minidump_memory_info_list *memory_info_list;
	struct minidump_module_list *module_list;
	struct minidump_thread_list *thread_list;
	struct minidump_thread_ex_list *thread_ex_list;
	struct minidump_thread_info_list *thread_info_list;
	struct minidump_unloaded_module_list *unloaded_module_list;

	struct avrf_handle_operation *handle_operations;
	struct minidump_memory_descriptor *memories;
	struct minidump_memory_descriptor64 *memories64;
	struct minidump_memory_info *memory_infos;
	struct minidump_module *modules;
	struct minidump_thread *threads;
	struct minidump_thread_ex *ex_threads;
	struct minidump_thread_info *thread_infos;
	struct minidump_unloaded_module *unloaded_modules;

	/* We could confirm data sizes but a malcious MDMP will always get around
	** this! But we can ensure that the data is not outside of the file */
	if (entry->location.rva + entry->location.data_size > obj->b->length) {
		eprintf("[ERROR] Size Mismatch - Stream data is larger than file size!\n");
		return false;
	}

	switch (entry->stream_type) {
	case THREAD_LIST_STREAM:
		thread_list = (struct minidump_thread_list *)(obj->b->buf + entry->location.rva);

		sdb_set (obj->kv, "mdmp_thread.format", "ddddq?? "
			"ThreadId SuspendCount PriorityClass Priority "
			"Teb (mdmp_memory_descriptor)Stack "
			"(mdmp_location_descriptor)ThreadContext", 0);
		sdb_num_set (obj->kv, "mdmp_thread_list.offset",
			entry->location.rva, 0);
		sdb_set (obj->kv, "mdmp_thread_list.format",
			sdb_fmt ("d[%i]? "
				"NumberOfThreads (mdmp_thread)Threads",
				thread_list->number_of_threads),
			0);

		/* TODO: Not yet fully parsed or utilised */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -362,7 +362,7 @@
 	/* We could confirm data sizes but a malcious MDMP will always get around
 	** this! But we can ensure that the data is not outside of the file */
 	if (entry->location.rva + entry->location.data_size > obj->b->length) {
-		eprintf("[ERROR] Size Mismatch - Stream data is larger than file size!\n");
+		eprintf ("[ERROR] Size Mismatch - Stream data is larger than file size!\n");
 		return false;
 	}
 
@@ -646,10 +646,7 @@
 
 static bool r_bin_mdmp_init_directory(struct r_bin_mdmp_obj *obj) {
 	int i;
-	ut8 *directory_base;
-	struct minidump_directory *entry;
-
-	directory_base = obj->b->buf + obj->hdr->stream_directory_rva;
+	struct minidump_directory entry;
 
 	sdb_num_set (obj->kv, "mdmp_directory.offset",
 			obj->hdr->stream_directory_rva, 0);
@@ -658,9 +655,13 @@
 			"(mdmp_location_descriptor)Location", 0);
 
 	/* Parse each entry in the directory */
+	ut64 rvadir = obj->hdr->stream_directory_rva;
 	for (i = 0; i < (int)obj->hdr->number_of_streams; i++) {
-		entry = (struct minidump_directory *)(directory_base + (i * sizeof (struct minidump_directory)));
-		r_bin_mdmp_init_directory_entry (obj, entry);
+		ut32 delta = i * sizeof (struct minidump_directory);
+		int r = r_buf_read_at (obj->b, rvadir + delta, (ut8*) &entry, sizeof (struct minidump_directory));
+		if (r) {
+			r_bin_mdmp_init_directory_entry (obj, &entry);
+		}
 	}
 
 	return true;
```
