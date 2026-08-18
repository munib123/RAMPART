# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 2191_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2191_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 61-105 of the vulnerable file.

	hba->hba_ptr = rd_host;

	pr_debug("CORE_HBA[%d] - TCM Ramdisk HBA Driver %s on"
		" Generic Target Core Stack %s\n", hba->hba_id,
		RD_HBA_VERSION, TARGET_CORE_MOD_VERSION);

	return 0;
}

static void rd_detach_hba(struct se_hba *hba)
{
	struct rd_host *rd_host = hba->hba_ptr;

	pr_debug("CORE_HBA[%d] - Detached Ramdisk HBA: %u from"
		" Generic Target Core\n", hba->hba_id, rd_host->rd_host_id);

	kfree(rd_host);
	hba->hba_ptr = NULL;
}

/*	rd_release_device_space():
 *
 *
 */
static void rd_release_device_space(struct rd_dev *rd_dev)
{
	u32 i, j, page_count = 0, sg_per_table;
	struct rd_dev_sg_table *sg_table;
	struct page *pg;
	struct scatterlist *sg;

	if (!rd_dev->sg_table_array || !rd_dev->sg_table_count)
		return;

	sg_table = rd_dev->sg_table_array;

	for (i = 0; i < rd_dev->sg_table_count; i++) {
		sg = sg_table[i].sg_table;
		sg_per_table = sg_table[i].rd_sg_count;

		for (j = 0; j < sg_per_table; j++) {
			pg = sg_page(&sg[j]);
			if (pg) {
				__free_page(pg);
				page_count++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,23 +78,14 @@
 	hba->hba_ptr = NULL;
 }
 
-/*	rd_release_device_space():
- *
- *
- */
-static void rd_release_device_space(struct rd_dev *rd_dev)
-{
-	u32 i, j, page_count = 0, sg_per_table;
-	struct rd_dev_sg_table *sg_table;
+static u32 rd_release_sgl_table(struct rd_dev *rd_dev, struct rd_dev_sg_table *sg_table,
+				 u32 sg_table_count)
+{
 	struct page *pg;
 	struct scatterlist *sg;
-
-	if (!rd_dev->sg_table_array || !rd_dev->sg_table_count)
-		return;
-
-	sg_table = rd_dev->sg_table_array;
-
-	for (i = 0; i < rd_dev->sg_table_count; i++) {
+	u32 i, j, page_count = 0, sg_per_table;
+
+	for (i = 0; i < sg_table_count; i++) {
 		sg = sg_table[i].sg_table;
 		sg_per_table = sg_table[i].rd_sg_count;
 
@@ -105,16 +96,28 @@
 				page_count++;
 			}
 		}
-
 		kfree(sg);
 	}
+
+	kfree(sg_table);
+	return page_count;
+}
+
+static void rd_release_device_space(struct rd_dev *rd_dev)
+{
+	u32 page_count;
+
+	if (!rd_dev->sg_table_array || !rd_dev->sg_table_count)
+		return;
+
+	page_count = rd_release_sgl_table(rd_dev, rd_dev->sg_table_array,
+					  rd_dev->sg_table_count);
 
 	pr_debug("CORE_RD[%u] - Released device space for Ramdisk"
 		" Device ID: %u, pages %u in %u tables total bytes %lu\n",
 		rd_dev->rd_host->rd_host_id, rd_dev->rd_dev_id, page_count,
 		rd_dev->sg_table_count, (unsigned long)page_count * PAGE_SIZE);
 
-	kfree(sg_table);
 	rd_dev->sg_table_array = NULL;
 	rd_dev->sg_table_count = 0;
 }
@@ -124,38 +127,15 @@
  *
  *
  */
-static int rd_build_device_space(struct rd_dev *rd_dev)
-{
-	u32 i = 0, j, page_offset = 0, sg_per_table, sg_tables, total_sg_needed;
+static int rd_allocate_sgl_table(struct rd_dev *rd_dev, struct rd_dev_sg_table *sg_table,
+				 u32 total_sg_needed, unsigned char init_payload)
+{
+	u32 i = 0, j, page_offset = 0, sg_per_table;
 	u32 max_sg_per_table = (RD_MAX_ALLOCATION_SIZE /
 				sizeof(struct scatterlist));
-	struct rd_dev_sg_table *sg_table;
 	struct page *pg;
 	struct scatterlist *sg;
-
-	if (rd_dev->rd_page_count <= 0) {
-		pr_err("Illegal page count: %u for Ramdisk device\n",
-			rd_dev->rd_page_count);
-		return -EINVAL;
-	}
-
-	/* Don't need backing pages for NULLIO */
-	if (rd_dev->rd_flags & RDF_NULLIO)
-		return 0;
-
-	total_sg_needed = rd_dev->rd_page_count;
-
-	sg_tables = (total_sg_needed / max_sg_per_table) + 1;
-
-	sg_table = kzalloc(sg_tables * sizeof(struct rd_dev_sg_table), GFP_KERNEL);
-	if (!sg_table) {
-		pr_err("Unable to allocate memory for Ramdisk"
-			" scatterlist tables\n");
-		return -ENOMEM;
-	}
-
-	rd_dev->sg_table_array = sg_table;
-	rd_dev->sg_table_count = sg_tables;
+	unsigned char *p;
 
 	while (total_sg_needed) {
 		sg_per_table = (total_sg_needed > max_sg_per_table) ?
@@ -186,16 +166,59 @@
 			}
 			sg_assign_page(&sg[j], pg);
 			sg[j].length = PAGE_SIZE;
+
+			p = kmap(pg);
+			memset(p, init_payload, PAGE_SIZE);
+			kunmap(pg);
 		}
 
 		page_offset += sg_per_table;
 		total_sg_needed -= sg_per_table;
 	}
 
+	return 0;
+}
+
+static int rd_build_device_space(struct rd_dev *rd_dev)
+{
+	struct rd_dev_sg_table *sg_table;
+	u32 sg_tables, total_sg_needed;
+	u32 max_sg_per_table = (RD_MAX_ALLOCATION_SIZE /
+				sizeof(struct scatterlist));
+	int rc;
+
+	if (rd_dev->rd_page_count <= 0) {
+		pr_err("Illegal page count: %u for Ramdisk device\n",
+		       rd_dev->rd_page_count);
+		return -EINVAL;
+	}
+
+	/* Don't need backing pages for NULLIO */
+	if (rd_dev->rd_flags & RDF_NULLIO)
+		return 0;
+
+	total_sg_needed = rd_dev->rd_page_count;
+
+	sg_tables = (total_sg_needed / max_sg_per_table) + 1;
+
+	sg_table = kzalloc(sg_tables * sizeof(struct rd_dev_sg_table), GFP_KERNEL);
+	if (!sg_table) {
+		pr_err("Unable to allocate memory for Ramdisk"
+		       " scatterlist tables\n");
+		return -ENOMEM;
+	}
+
+	rd_dev->sg_table_array = sg_table;
+	rd_dev->sg_table_count = sg_tables;
+
+	rc = rd_allocate_sgl_table(rd_dev, sg_table, total_sg_needed, 0x00);
+	if (rc)
+		return rc;
+
 	pr_debug("CORE_RD[%u] - Built Ramdisk Device ID: %u space of"
-		" %u pages in %u tables\n", rd_dev->rd_host->rd_host_id,
-		rd_dev->rd_dev_id, rd_dev->rd_page_count,
-		rd_dev->sg_table_count);
+		 " %u pages in %u tables\n", rd_dev->rd_host->rd_host_id,
+		 rd_dev->rd_dev_id, rd_dev->rd_page_count,
+		 rd_dev->sg_table_count);
 
 	return 0;
 }
```
