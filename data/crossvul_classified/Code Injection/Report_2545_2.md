# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in json
**Pair ID:** 2545_2
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** json
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2545_2`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```json
Lines 76-116 of the vulnerable file.

    "mathematics",
    "functions",
    "numeric",
    "algebra",
    "parser",
    "expression",
    "number",
    "bignumber",
    "complex",
    "fraction",
    "matrix",
    "unit"
  ],
  "dependencies": {
    "complex.js": "2.0.4",
    "decimal.js": "7.2.3",
    "fraction.js": "4.0.2",
    "javascript-natural-sort": "0.7.1",
    "seed-random": "2.2.0",
    "tiny-emitter": "2.0.0",
    "typed-function": "0.10.5"
  },
  "devDependencies": {
    "benchmark": "2.1.4",
    "expr-eval": "1.0.1",
    "glob": "7.1.2",
    "gulp": "3.9.1",
    "gulp-util": "3.0.8",
    "istanbul": "0.4.5",
    "jsep": "0.3.0",
    "math-expression-evaluator": "1.2.17",
    "mkdirp": "0.5.1",
    "mocha": "3.4.2",
    "ndarray": "1.0.18",
    "ndarray-determinant": "1.0.0",
    "ndarray-gemm": "1.0.0",
    "ndarray-ops": "1.2.2",
    "ndarray-pack": "1.2.1",
    "numericjs": "1.2.6",
    "pad-right": "0.2.2",
    "q": "1.5.0",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -93,7 +93,7 @@
     "javascript-natural-sort": "0.7.1",
     "seed-random": "2.2.0",
     "tiny-emitter": "2.0.0",
-    "typed-function": "0.10.5"
+    "typed-function": "0.10.6"
   },
   "devDependencies": {
     "benchmark": "2.1.4",
```
