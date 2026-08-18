# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 539_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `539_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 68-108 of the vulnerable file.

@return returns false if pi pointed to the last packet or else returns true
*/
static opj_bool pi_next_pcrl(opj_pi_iterator_t * pi);
/**
Get next packet in component-precinct-resolution-layer order.
@param pi packet iterator to modify
@return returns false if pi pointed to the last packet or else returns true
*/
static opj_bool pi_next_cprl(opj_pi_iterator_t * pi);

/*@}*/

/*@}*/

/*
==========================================================
   local functions
==========================================================
*/

static opj_bool pi_next_lrcp(opj_pi_iterator_t * pi)
{
    opj_pi_comp_t *comp = NULL;
    opj_pi_resolution_t *res = NULL;
    long index = 0;

    if (!pi->first) {
        comp = &pi->comps[pi->compno];
        res = &comp->resolutions[pi->resno];
        goto LABEL_SKIP;
    } else {
        pi->first = 0;
    }

    for (pi->layno = pi->poc.layno0; pi->layno < pi->poc.layno1; pi->layno++) {
        for (pi->resno = pi->poc.resno0; pi->resno < pi->poc.resno1;
                pi->resno++) {
            for (pi->compno = pi->poc.compno0; pi->compno < pi->poc.compno1; pi->compno++) {
                comp = &pi->comps[pi->compno];
                if (pi->resno >= comp->numresolutions) {
                    continue;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -85,6 +85,12 @@
 ==========================================================
 */
 
+static void opj_pi_emit_error(opj_pi_iterator_t * pi, const char* msg)
+{
+    (void)pi;
+    (void)msg;
+}
+
 static opj_bool pi_next_lrcp(opj_pi_iterator_t * pi)
 {
     opj_pi_comp_t *comp = NULL;
@@ -114,6 +120,11 @@
                 for (pi->precno = pi->poc.precno0; pi->precno < pi->poc.precno1; pi->precno++) {
                     index = pi->layno * pi->step_l + pi->resno * pi->step_r + pi->compno *
                             pi->step_c + pi->precno * pi->step_p;
+                    /* Avoids index out of bounds access with include*/
+                    if (index >= pi->include_size) {
+                        opj_pi_emit_error(pi, "Invalid access to pi->include");
+                        return OPJ_FALSE;
+                    }
                     if (!pi->include[index]) {
                         pi->include[index] = 1;
                         return OPJ_TRUE;
@@ -156,6 +167,11 @@
                 for (pi->precno = pi->poc.precno0; pi->precno < pi->poc.precno1; pi->precno++) {
                     index = pi->layno * pi->step_l + pi->resno * pi->step_r + pi->compno *
                             pi->step_c + pi->precno * pi->step_p;
+                    /* Avoids index out of bounds access with include*/
+                    if (index >= pi->include_size) {
+                        opj_pi_emit_error(pi, "Invalid access to pi->include");
+                        return OPJ_FALSE;
+                    }
                     if (!pi->include[index]) {
                         pi->include[index] = 1;
                         return OPJ_TRUE;
@@ -256,6 +272,11 @@
                     for (pi->layno = pi->poc.layno0; pi->layno < pi->poc.layno1; pi->layno++) {
                         index = pi->layno * pi->step_l + pi->resno * pi->step_r + pi->compno *
                                 pi->step_c + pi->precno * pi->step_p;
+                        /* Avoids index out of bounds access with include*/
+                        if (index >= pi->include_size) {
+                            opj_pi_emit_error(pi, "Invalid access to pi->include");
+                            return OPJ_FALSE;
+                        }
                         if (!pi->include[index]) {
                             pi->include[index] = 1;
                             return OPJ_TRUE;
@@ -356,6 +377,11 @@
                     for (pi->layno = pi->poc.layno0; pi->layno < pi->poc.layno1; pi->layno++) {
                         index = pi->layno * pi->step_l + pi->resno * pi->step_r + pi->compno *
                                 pi->step_c + pi->precno * pi->step_p;
+                        /* Avoids index out of bounds access with include*/
+                        if (index >= pi->include_size) {
+                            opj_pi_emit_error(pi, "Invalid access to pi->include");
+                            return OPJ_FALSE;
+                        }
                         if (!pi->include[index]) {
                             pi->include[index] = 1;
                             return OPJ_TRUE;
@@ -454,6 +480,11 @@
                     for (pi->layno = pi->poc.layno0; pi->layno < pi->poc.layno1; pi->layno++) {
                         index = pi->layno * pi->step_l + pi->resno * pi->step_r + pi->compno *
                                 pi->step_c + pi->precno * pi->step_p;
+                        /* Avoids index out of bounds access with include*/
+                        if (index >= pi->include_size) {
+                            opj_pi_emit_error(pi, "Invalid access to pi->include");
+                            return OPJ_FALSE;
+                        }
                         if (!pi->include[index]) {
                             pi->include[index] = 1;
                             return OPJ_TRUE;
```
