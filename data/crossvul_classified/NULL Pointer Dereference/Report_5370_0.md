# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 5370_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5370_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 84-124 of the vulnerable file.

\******************************************************************************/

jas_matrix_t *jas_seq2d_create(int xstart, int ystart, int xend, int yend)
{
	jas_matrix_t *matrix;
	assert(xstart <= xend && ystart <= yend);
	if (!(matrix = jas_matrix_create(yend - ystart, xend - xstart))) {
		return 0;
	}
	matrix->xstart_ = xstart;
	matrix->ystart_ = ystart;
	matrix->xend_ = xend;
	matrix->yend_ = yend;
	return matrix;
}

jas_matrix_t *jas_matrix_create(int numrows, int numcols)
{
	jas_matrix_t *matrix;
	int i;

	if (!(matrix = jas_malloc(sizeof(jas_matrix_t)))) {
		return 0;
	}
	matrix->flags_ = 0;
	matrix->numrows_ = numrows;
	matrix->numcols_ = numcols;
	matrix->rows_ = 0;
	matrix->maxrows_ = numrows;
	matrix->data_ = 0;
	matrix->datasize_ = numrows * numcols;

	if (matrix->maxrows_ > 0) {
		if (!(matrix->rows_ = jas_alloc2(matrix->maxrows_,
		  sizeof(jas_seqent_t *)))) {
			jas_matrix_destroy(matrix);
			return 0;
		}
	}

	if (matrix->datasize_ > 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -102,6 +102,10 @@
 	jas_matrix_t *matrix;
 	int i;
 
+	if (numrows < 0 || numcols < 0) {
+		return 0;
+	}
+
 	if (!(matrix = jas_malloc(sizeof(jas_matrix_t)))) {
 		return 0;
 	}
```
