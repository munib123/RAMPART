# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 4937_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4937_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 83-126 of the vulnerable file.

}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	pgtable_pmd_page_dtor(virt_to_page(pmd));
	crst_table_free(mm, (unsigned long *) pmd);
}

static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	pgd_val(*pgd) = _REGION2_ENTRY | __pa(pud);
}

static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	pud_val(*pud) = _REGION3_ENTRY | __pa(pmd);
}

static inline pgd_t *pgd_alloc(struct mm_struct *mm)
{
	spin_lock_init(&mm->context.list_lock);
	INIT_LIST_HEAD(&mm->context.pgtable_list);
	INIT_LIST_HEAD(&mm->context.gmap_list);
	return (pgd_t *) crst_table_alloc(mm);
}
#define pgd_free(mm, pgd) crst_table_free(mm, (unsigned long *) pgd)

static inline void pmd_populate(struct mm_struct *mm,
				pmd_t *pmd, pgtable_t pte)
{
	pmd_val(*pmd) = _SEGMENT_ENTRY + __pa(pte);
}

#define pmd_populate_kernel(mm, pmd, pte) pmd_populate(mm, pmd, pte)

#define pmd_pgtable(pmd) \
	(pgtable_t)(pmd_val(pmd) & -sizeof(pte_t)*PTRS_PER_PTE)

/*
 * page table entry allocation/free routines.
 */
#define pte_alloc_one_kernel(mm, vmaddr) ((pte_t *) page_table_alloc(mm))
#define pte_alloc_one(mm, vmaddr) ((pte_t *) page_table_alloc(mm))

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -100,12 +100,26 @@
 
 static inline pgd_t *pgd_alloc(struct mm_struct *mm)
 {
-	spin_lock_init(&mm->context.list_lock);
-	INIT_LIST_HEAD(&mm->context.pgtable_list);
-	INIT_LIST_HEAD(&mm->context.gmap_list);
-	return (pgd_t *) crst_table_alloc(mm);
+	unsigned long *table = crst_table_alloc(mm);
+
+	if (!table)
+		return NULL;
+	if (mm->context.asce_limit == (1UL << 31)) {
+		/* Forking a compat process with 2 page table levels */
+		if (!pgtable_pmd_page_ctor(virt_to_page(table))) {
+			crst_table_free(mm, table);
+			return NULL;
+		}
+	}
+	return (pgd_t *) table;
 }
-#define pgd_free(mm, pgd) crst_table_free(mm, (unsigned long *) pgd)
+
+static inline void pgd_free(struct mm_struct *mm, pgd_t *pgd)
+{
+	if (mm->context.asce_limit == (1UL << 31))
+		pgtable_pmd_page_dtor(virt_to_page(pgd));
+	crst_table_free(mm, (unsigned long *) pgd);
+}
 
 static inline void pmd_populate(struct mm_struct *mm,
 				pmd_t *pmd, pgtable_t pte)
```
