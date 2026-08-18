# CrossVul Fix Pair: Improper Validation of Integrity Check Value in c
**Pair ID:** 1210_0
**Vulnerability Class:** Insufficient Verification of Data Authenticity
**CWE:** CWE-354
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1210_0`)

## Vulnerability Information & PoC

## Description
Improper Validation of Integrity Check Value - Improper validation of checksums before use results in an unnecessary risk that can easily be mitigated.

## Vulnerable Code
```c
Lines 19-59 of the vulnerable file.


#include "keepkey/board/keepkey_board.h"
#include "keepkey/board/layout.h"
#include "keepkey/board/messages.h"
#include "trezor/crypto/bip39.h"
#include "trezor/crypto/memzero.h"
#include "keepkey/firmware/app_layout.h"
#include "keepkey/board/confirm_sm.h"
#include "keepkey/firmware/fsm.h"
#include "keepkey/firmware/home_sm.h"
#include "keepkey/firmware/pin_sm.h"
#include "keepkey/firmware/recovery_cipher.h"
#include "keepkey/firmware/storage.h"
#include "keepkey/rand/rng.h"

#include <string.h>
#include <stdio.h>

#define MAX_UNCYPHERED_WORDS (3)

static bool enforce_wordlist;
static bool dry_run;
static bool awaiting_character;
static CONFIDENTIAL char mnemonic[MNEMONIC_BUF];
static char english_alphabet[ENGLISH_ALPHABET_BUF] = "abcdefghijklmnopqrstuvwxyz";
static CONFIDENTIAL char cipher[ENGLISH_ALPHABET_BUF];

#if DEBUG_LINK
static char auto_completed_word[CURRENT_WORD_BUF];
#endif

static void format_current_word(char *current_word, bool auto_completed);
static uint32_t get_current_word_pos(void);
static void get_current_word(char *current_word);

static void recovery_abort(void) {
    if (!dry_run) {
        storage_reset();
    }

    awaiting_character = false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,6 +36,7 @@
 
 #define MAX_UNCYPHERED_WORDS (3)
 
+static bool recovery_started = false;
 static bool enforce_wordlist;
 static bool dry_run;
 static bool awaiting_character;
@@ -56,6 +57,7 @@
         storage_reset();
     }
 
+    recovery_started = false;
     awaiting_character = false;
     memzero(mnemonic, sizeof(mnemonic));
     memzero(cipher, sizeof(cipher));
@@ -270,6 +272,7 @@
 
     /* Set to recovery cipher mode and generate and show next cipher */
     awaiting_character = true;
+    recovery_started = true;
     next_character();
 }
 
@@ -283,6 +286,13 @@
  */
 void next_character(void)
 {
+    if (!recovery_started) {
+        recovery_abort();
+        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Not in Recovery mode");
+        layoutHome();
+        return;
+    }
+
     /* Scramble cipher */
     strlcpy(cipher, english_alphabet, ENGLISH_ALPHABET_BUF);
     random_permute_char(cipher, strlen(cipher));
@@ -341,7 +351,7 @@
  */
 void recovery_character(const char *character)
 {
-    if (!awaiting_character) {
+    if (!awaiting_character || !recovery_started) {
         recovery_abort();
         fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Not in Recovery mode");
         layoutHome();
@@ -430,6 +440,13 @@
  */
 void recovery_delete_character(void)
 {
+    if (!recovery_started) {
+        recovery_abort();
+        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Not in Recovery mode");
+        layoutHome();
+        return;
+    }
+
     if(strlen(mnemonic) > 0)
     {
         mnemonic[strlen(mnemonic) - 1] = '\0';
@@ -448,6 +465,13 @@
  */
 void recovery_cipher_finalize(void)
 {
+    if (!recovery_started) {
+        recovery_abort();
+        fsm_sendFailure(FailureType_Failure_UnexpectedMessage, "Not in Recovery mode");
+        layoutHome();
+        return;
+    }
+
     static char CONFIDENTIAL new_mnemonic[MNEMONIC_BUF] = "";
     static char CONFIDENTIAL temp_word[CURRENT_WORD_BUF];
     volatile bool auto_completed = true;
@@ -479,7 +503,7 @@
     }
 
     /* Truncate additional space at the end */
-    new_mnemonic[strlen(new_mnemonic) - 1] = '\0';
+    new_mnemonic[MAX(0u, strnlen(new_mnemonic, sizeof(new_mnemonic)) - 1)] = '\0';
 
     if (!dry_run && (!enforce_wordlist || mnemonic_check(new_mnemonic))) {
         storage_setMnemonic(new_mnemonic);
@@ -532,6 +556,8 @@
  */
 bool recovery_cipher_abort(void)
 {
+    recovery_started = false;
+
     if (awaiting_character) {
         awaiting_character = false;
         return true;
```
