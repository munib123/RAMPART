# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5342_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5342_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 727-767 of the vulnerable file.

}

/**
 * \brief Solve least squares problem for kernel of the main filter
 * \param mu out: output coefficients
 * \param index in: filter tap positions
 * \param prefilter in: supplementary filter type
 * \param r2 in: desired standard deviation squared
 * \param mul in: scale multiplier
 */
static void calc_coeff(double mu[4], const int index[4], int prefilter, double r2, double mul)
{
    double mul2 = mul * mul, mul3 = mul2 * mul;
    double kernel[] = {
        (5204 + 2520 * mul + 1092 * mul2 + 3280 * mul3) / 12096,
        (2943 -  210 * mul -  273 * mul2 - 2460 * mul3) / 12096,
        ( 486 -  924 * mul -  546 * mul2 +  984 * mul3) / 12096,
        (  17 -  126 * mul +  273 * mul2 -  164 * mul3) / 12096,
    };

    double mat_freq[13];
    memcpy(mat_freq, kernel, sizeof(kernel));
    memset(mat_freq + 4, 0, sizeof(mat_freq) - sizeof(kernel));
    int n = 6;
    coeff_filter(mat_freq, n, kernel);
    for (int k = 0; k < 2 * prefilter; ++k)
        coeff_blur121(mat_freq, ++n);

    double vec_freq[13];
    n = index[3] + prefilter + 3;
    calc_gauss(vec_freq, n, r2);
    memset(vec_freq + n + 1, 0, sizeof(vec_freq) - (n + 1) * sizeof(vec_freq[0]));
    n -= 3;
    coeff_filter(vec_freq, n, kernel);
    for (int k = 0; k < prefilter; ++k)
        coeff_blur121(vec_freq, --n);

    double mat[4][4];
    calc_matrix(mat, mat_freq, index);

    double vec[4];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -744,7 +744,7 @@
         (  17 -  126 * mul +  273 * mul2 -  164 * mul3) / 12096,
     };
 
-    double mat_freq[13];
+    double mat_freq[14];
     memcpy(mat_freq, kernel, sizeof(kernel));
     memset(mat_freq + 4, 0, sizeof(mat_freq) - sizeof(kernel));
     int n = 6;
```
