# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 976_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `976_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 1230-1270 of the vulnerable file.

		// withdraw template
		Process_ipfix_template_withdraw(exporter, DataPtr, size_left, fs);
	} else {
		// refresh/add templates
		Process_ipfix_template_add(exporter, DataPtr, size_left, fs);
	}

} // End of Process_ipfix_templates

static void Process_ipfix_template_add(exporter_ipfix_domain_t *exporter, void *DataPtr, uint32_t size_left, FlowSource_t *fs) {
input_translation_t *translation_table;
ipfix_template_record_t *ipfix_template_record;
ipfix_template_elements_std_t *NextElement;
int i;

	// a template flowset can contain multiple records ( templates )
	while ( size_left ) {
		uint32_t table_id, count, size_required;
		uint32_t num_extensions = 0;

		if ( size_left && size_left < 4 ) {
			LogError("Process_ipfix [%u] Template size error at %s line %u" , 
				exporter->info.id, __FILE__, __LINE__, strerror (errno));
			size_left = 0;
			continue;
		}

		// map next record.
		ipfix_template_record = (ipfix_template_record_t *)DataPtr;
		size_left 		-= 4;

		table_id = ntohs(ipfix_template_record->TemplateID);
		count	 = ntohs(ipfix_template_record->FieldCount);

		dbg_printf("\n[%u] Template ID: %u\n", exporter->info.id, table_id);
		dbg_printf("FieldCount: %u buffersize: %u\n", count, size_left);

		// prepare
		// clear helper tables
		memset((void *)cache.common_extensions, 0,  (Max_num_extensions+1)*sizeof(uint32_t));
		memset((void *)cache.lookup_info, 0, 65536 * sizeof(struct element_param_s));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1247,7 +1247,7 @@
 		uint32_t table_id, count, size_required;
 		uint32_t num_extensions = 0;
 
-		if ( size_left && size_left < 4 ) {
+		if ( size_left < 4 ) {
 			LogError("Process_ipfix [%u] Template size error at %s line %u" , 
 				exporter->info.id, __FILE__, __LINE__, strerror (errno));
 			size_left = 0;
@@ -1426,6 +1426,14 @@
 	while ( size_left ) {
 		uint32_t id;
 
+		if ( size_left < 4 ) {
+			LogError("Process_ipfix [%u] Template withdraw size error at %s line %u" , 
+				exporter->info.id, __FILE__, __LINE__, strerror (errno));
+			size_left = 0;
+			continue;
+		}
+
+
 		// map next record.
 		ipfix_template_record = (ipfix_template_record_t *)DataPtr;
 		size_left 		-= 4;
```
