# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 4850_1
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4850_1`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

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

	if (numrows < 0 || numcols < 0) {
		return 0;
	}

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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,13 +101,16 @@
 {
 	jas_matrix_t *matrix;
 	int i;
+	size_t size;
+
+	matrix = 0;
 
 	if (numrows < 0 || numcols < 0) {
-		return 0;
+		goto error;
 	}
 
 	if (!(matrix = jas_malloc(sizeof(jas_matrix_t)))) {
-		return 0;
+		goto error;
 	}
 	matrix->flags_ = 0;
 	matrix->numrows_ = numrows;
@@ -115,21 +118,25 @@
 	matrix->rows_ = 0;
 	matrix->maxrows_ = numrows;
 	matrix->data_ = 0;
-	matrix->datasize_ = numrows * numcols;
+	matrix->datasize_ = 0;
+
+	// matrix->datasize_ = numrows * numcols;
+	if (!jas_safe_size_mul(numrows, numcols, &size)) {
+		goto error;
+	}
+	matrix->datasize_ = size;
 
 	if (matrix->maxrows_ > 0) {
 		if (!(matrix->rows_ = jas_alloc2(matrix->maxrows_,
 		  sizeof(jas_seqent_t *)))) {
-			jas_matrix_destroy(matrix);
-			return 0;
+			goto error;
 		}
 	}
 
 	if (matrix->datasize_ > 0) {
 		if (!(matrix->data_ = jas_alloc2(matrix->datasize_,
 		  sizeof(jas_seqent_t)))) {
-			jas_matrix_destroy(matrix);
-			return 0;
+			goto error;
 		}
 	}
 
@@ -147,6 +154,12 @@
 	matrix->yend_ = matrix->numrows_;
 
 	return matrix;
+
+error:
+	if (matrix) {
+		jas_matrix_destroy(matrix);
+	}
+	return 0;
 }
 
 void jas_matrix_destroy(jas_matrix_t *matrix)
```
