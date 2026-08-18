# CrossVul Fix Pair: Integer Overflow or Wraparound in c
**Pair ID:** 3983_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3983_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```c
Lines 155-195 of the vulnerable file.

#define ARRAY_INDEX_STACK_SIZE 1024

#define DOC_PUSH_STATE(return_state) ( doc_stack[doc_stack_pointer++] = (return_state) )
#define DOC_POP_STATE ( state = doc_stack[--doc_stack_pointer] )
#define ARRAY_PUSH_RESET_INDEX_STATE(return_state) ( array_index_stack[array_index_stack_pointer++] = array_index, array_index = 0, DOC_PUSH_STATE(return_state) )
#define ARRAY_POP_INDEX_STATE ( array_index = array_index_stack[--array_index_stack_pointer], DOC_POP_STATE )

#define ARRAY_KEY_STRING(l) (bson_numstr(array_index_buffer, (int)(l)), array_index_buffer)

/*
 * simplified FSM to parse BCON structure, uses stacks for sub-documents and sub-arrays
 */
static bcon_error_t bson_append_bcon_with_state(bson *b, const bcon *bc, bcon_state_t start_state) {
    bcon_error_t ret = BCON_OK;
    bcon_state_t state = start_state;
    char *key = 0;
    char *typespec = 0;
    unsigned char doc_stack[DOC_STACK_SIZE];
    size_t doc_stack_pointer = 0;
    size_t array_index = 0;
    unsigned int array_index_stack[ARRAY_INDEX_STACK_SIZE];
    size_t array_index_stack_pointer = 0;
    char array_index_buffer[ARRAY_INDEX_BUFFER_SIZE]; /* max BSON size */
    int end_of_data;
    const bcon *bcp;
    for (end_of_data = 0, bcp = bc; ret == BCON_OK && !end_of_data; bcp++) {
        bcon bci = *bcp;
        char *s = bci.s;
        switch (state) {
        case State_Element:
            switch (bcon_token(s)) {
            case Token_CloseBrace:
                bson_append_finish_object( b );
                DOC_POP_STATE; /* state = ...; */
                break;
            case Token_End:
                end_of_data = 1;
                break;
            default:
                key = s;
                state = State_DocSpecValue;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -172,7 +172,7 @@
     unsigned char doc_stack[DOC_STACK_SIZE];
     size_t doc_stack_pointer = 0;
     size_t array_index = 0;
-    unsigned int array_index_stack[ARRAY_INDEX_STACK_SIZE];
+    size_t array_index_stack[ARRAY_INDEX_STACK_SIZE];
     size_t array_index_stack_pointer = 0;
     char array_index_buffer[ARRAY_INDEX_BUFFER_SIZE]; /* max BSON size */
     int end_of_data;
```
