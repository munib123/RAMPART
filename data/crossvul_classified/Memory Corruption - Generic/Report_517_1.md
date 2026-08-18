# CrossVul Fix Pair: Out-of-bounds Write in cpp
**Pair ID:** 517_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `517_1`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```cpp
Lines 1-33 of the vulnerable file.

#include "Enclave_t.h"

#include <cstdint>
#include <cassert>

#include "Aggregate.h"
#include "Crypto.h"
#include "Filter.h"
#include "Join.h"
#include "Project.h"
#include "Sort.h"
#include "isv_enclave.h"
#include "util.h"

// This file contains definitions of the ecalls declared in Enclave.edl. Errors originating within
// these ecalls are signaled by throwing a std::runtime_error, which is caught at the top level of
// the ecall (i.e., within these definitions), and are then rethrown as Java exceptions using
// ocall_throw.

void ecall_encrypt(uint8_t *plaintext, uint32_t plaintext_length,
                   uint8_t *ciphertext, uint32_t cipher_length) {
  try {
    // IV (12 bytes) + ciphertext + mac (16 bytes)
    assert(cipher_length >= plaintext_length + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
    (void)cipher_length;
    (void)plaintext_length;
    encrypt(plaintext, plaintext_length, ciphertext);
  } catch (const std::runtime_error &e) {
    ocall_throw(e.what());
  }
}

void ecall_project(uint8_t *condition, size_t condition_length,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -10,6 +10,7 @@
 #include "Project.h"
 #include "Sort.h"
 #include "isv_enclave.h"
+#include "sgx_lfence.h"
 #include "util.h"
 
 // This file contains definitions of the ecalls declared in Enclave.edl. Errors originating within
@@ -19,6 +20,11 @@
 
 void ecall_encrypt(uint8_t *plaintext, uint32_t plaintext_length,
                    uint8_t *ciphertext, uint32_t cipher_length) {
+  // Guard against encrypting or overwriting enclave memory
+  assert(sgx_is_outside_enclave(plaintext, plaintext_length) == 1);
+  assert(sgx_is_outside_enclave(ciphertext, cipher_length) == 1);
+  sgx_lfence();
+
   try {
     // IV (12 bytes) + ciphertext + mac (16 bytes)
     assert(cipher_length >= plaintext_length + SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE);
@@ -33,6 +39,10 @@
 void ecall_project(uint8_t *condition, size_t condition_length,
                    uint8_t *input_rows, size_t input_rows_length,
                    uint8_t **output_rows, size_t *output_rows_length) {
+  // Guard against operating on arbitrary enclave memory
+  assert(sgx_is_outside_enclave(input_rows, input_rows_length) == 1);
+  sgx_lfence();
+
   try {
     project(condition, condition_length,
             input_rows, input_rows_length,
@@ -45,6 +55,10 @@
 void ecall_filter(uint8_t *condition, size_t condition_length,
                   uint8_t *input_rows, size_t input_rows_length,
                   uint8_t **output_rows, size_t *output_rows_length) {
+  // Guard against operating on arbitrary enclave memory
+  assert(sgx_is_outside_enclave(input_rows, input_rows_length) == 1);
+  sgx_lfence();
+
   try {
     filter(condition, condition_length,
            input_rows, input_rows_length,
@@ -56,6 +70,10 @@
 
 void ecall_sample(uint8_t *input_rows, size_t input_rows_length,
                   uint8_t **output_rows, size_t *output_rows_length) {
+  // Guard against operating on arbitrary enclave memory
+  assert(sgx_is_outside_enclave(input_rows, input_rows_length) == 1);
+  sgx_lfence();
+
   try {
     sample(input_rows, input_rows_length,
            output_rows, output_rows_length);
@@ -68,6 +86,10 @@
                              uint32_t num_partitions,
                              uint8_t *input_rows, size_t input_rows_length,
                              uint8_t **output_rows, size_t *output_rows_length) {
+  // Guard against operating on arbitrary enclave memory
+  assert(sgx_is_outside_enclave(input_rows, input_rows_length) == 1);
+  sgx_lfence();
+
   try {
     find_range_bounds(sort_order, sort_order_length,
                       num_partitions,
@@ -83,6 +105,11 @@
                               uint8_t *input_rows, size_t input_rows_length,
                               uint8_t *boundary_rows, size_t boundary_rows_length,
                               uint8_t **output_partitions, size_t *output_partition_lengths) {
+  // Guard against operating on arbitrary enclave memory
+  assert(sgx_is_outside_enclave(input_rows, input_rows_length) == 1);
+  assert(sgx_is_outside_enclave(boundary_rows, boundary_rows_length) == 1);
+  sgx_lfence();
+
   try {
     partition_for_sort(sort_order, sort_order_length,
                        num_partitions,
@@ -97,6 +124,10 @@
 void ecall_external_sort(uint8_t *sort_order, size_t sort_order_length,
                          uint8_t *input_rows, size_t input_rows_length,
                          uint8_t **output_rows, size_t *output_rows_length) {
+  // Guard against operating on arbitrary enclave memory
+  assert(sgx_is_outside_enclave(input_rows, input_rows_length) == 1);
+  sgx_lfence();
+
   try {
     external_sort(sort_order, sort_order_length,
                   input_rows, input_rows_length,
@@ -109,6 +140,10 @@
 void ecall_scan_collect_last_primary(uint8_t *join_expr, size_t join_expr_length,
                                      uint8_t *input_rows, size_t input_rows_length,
                                      uint8_t **output_rows, size_t *output_rows_length) {
+  // Guard against operating on arbitrary enclave memory
+  assert(sgx_is_outside_enclave(input_rows, input_rows_length) == 1);
+  sgx_lfence();
+
   try {
     scan_collect_last_primary(join_expr, join_expr_length,
                               input_rows, input_rows_length,
@@ -122,6 +157,11 @@
                                          uint8_t *input_rows, size_t input_rows_length,
                                          uint8_t *join_row, size_t join_row_length,
                                          uint8_t **output_rows, size_t *output_rows_length) {
+  // Guard against operating on arbitrary enclave memory
+  assert(sgx_is_outside_enclave(input_rows, input_rows_length) == 1);
+  assert(sgx_is_outside_enclave(join_row, join_row_length) == 1);
+  sgx_lfence();
+
   try {
     non_oblivious_sort_merge_join(join_expr, join_expr_length,
                                   input_rows, input_rows_length,
@@ -138,6 +178,10 @@
   uint8_t **first_row, size_t *first_row_length,
   uint8_t **last_group, size_t *last_group_length,
   uint8_t **last_row, size_t *last_row_length) {
+  // Guard against operating on arbitrary enclave memory
+  assert(sgx_is_outside_enclave(input_rows, input_rows_length) == 1);
+  sgx_lfence();
+
   try {
     non_oblivious_aggregate_step1(
       agg_op, agg_op_length,
@@ -157,6 +201,13 @@
   uint8_t *prev_partition_last_group, size_t prev_partition_last_group_length,
   uint8_t *prev_partition_last_row, size_t prev_partition_last_row_length,
   uint8_t **output_rows, size_t *output_rows_length) {
+  // Guard against operating on arbitrary enclave memory
+  assert(sgx_is_outside_enclave(input_rows, input_rows_length) == 1);
+  assert(sgx_is_outside_enclave(next_partition_first_row, next_partition_first_row_length) == 1);
+  assert(sgx_is_outside_enclave(prev_partition_last_group, prev_partition_last_group_length) == 1);
+  assert(sgx_is_outside_enclave(prev_partition_last_row, prev_partition_last_row_length) == 1);
+  sgx_lfence();
+
   try {
     non_oblivious_aggregate_step2(
       agg_op, agg_op_length,
```
