# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 4849_1
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4849_1`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 137-177 of the vulnerable file.

	/* The allocated size of the data array. */
	int_fast32_t datasize_;

} jas_matrix_t;

typedef jas_matrix_t jas_seq2d_t;
typedef jas_matrix_t jas_seq_t;

/******************************************************************************\
* Functions/macros for matrix class.
\******************************************************************************/

/* Get the number of rows. */
#define jas_matrix_numrows(matrix) \
	((matrix)->numrows_)

/* Get the number of columns. */
#define jas_matrix_numcols(matrix) \
	((matrix)->numcols_)

/* Get a matrix element. */
#define jas_matrix_get(matrix, i, j) \
	((matrix)->rows_[i][j])

/* Set a matrix element. */
#define jas_matrix_set(matrix, i, j, v) \
	((matrix)->rows_[i][j] = (v))

/* Get an element from a matrix that is known to be a row or column vector. */
#define jas_matrix_getv(matrix, i) \
	(((matrix)->numrows_ == 1) ? ((matrix)->rows_[0][i]) : \
	  ((matrix)->rows_[i][0]))

/* Set an element in a matrix that is known to be a row or column vector. */
#define jas_matrix_setv(matrix, i, v) \
	(((matrix)->numrows_ == 1) ? ((matrix)->rows_[0][i] = (v)) : \
	  ((matrix)->rows_[i][0] = (v)))

/* Get the address of an element in a matrix. */
#define	jas_matrix_getref(matrix, i, j) \
	(&(matrix)->rows_[i][j])
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -154,6 +154,9 @@
 #define jas_matrix_numcols(matrix) \
 	((matrix)->numcols_)
 
+#define jas_matrix_size(matrix) \
+	(jas_matrix_width(matrix) * jas_matrix_height(matrix))
+
 /* Get a matrix element. */
 #define jas_matrix_get(matrix, i, j) \
 	((matrix)->rows_[i][j])
@@ -269,6 +272,8 @@
 	((s)->xstart_ = (x), (s)->ystart_ = (y), \
 	  (s)->xend_ = (s)->xstart_ + (s)->numcols_, \
 	  (s)->yend_ = (s)->ystart_ + (s)->numrows_)
+#define jas_seq2d_size(s) \
+	(jas_seq2d_width(s) * jas_seq2d_height(s))
 
 void jas_seq2d_bindsub(jas_matrix_t *s, jas_matrix_t *s1, int xstart,
   int ystart, int xend, int yend);
```
