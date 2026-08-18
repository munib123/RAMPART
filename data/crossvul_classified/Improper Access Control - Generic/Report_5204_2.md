# CrossVul Fix Pair: Improper Access Control in c
**Pair ID:** 5204_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-284
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5204_2`)

## Vulnerability Information & PoC

## Description
Improper Access Control - Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Ac...

## Vulnerable Code
```c
Lines 1352-1392 of the vulnerable file.

	char *filename,
	/*! Send Instruction object which gives information whether the file
	 * is a virtual file or not. */
	struct SendInstruction *Instr)
{
	size_t Data_Buf_Size = 1024;
	char Buf[1024];
	int Timeout = -1;
	FILE *Fp;
	parse_status_t status = PARSE_OK;
	int ok_on_close = FALSE;
	size_t entity_offset = 0;
	int num_read = 0;
	int ret_code = HTTP_OK;

	if (Instr && Instr->IsVirtualFile) {
		Fp = (virtualDirCallback.open) (filename, UPNP_WRITE);
		if (Fp == NULL)
			return HTTP_INTERNAL_SERVER_ERROR;
	} else {
		Fp = fopen(filename, "wb");
		if (Fp == NULL)
			return HTTP_UNAUTHORIZED;
	}
	parser->position = POS_ENTITY;
	do {
		/* first parse what has already been gotten */
		if (parser->position != POS_COMPLETE)
			status = parser_parse_entity(parser);
		if (status == PARSE_INCOMPLETE_ENTITY) {
			/* read until close */
			ok_on_close = TRUE;
		} else if ((status != PARSE_SUCCESS)
			   && (status != PARSE_CONTINUE_1)
			   && (status != PARSE_INCOMPLETE)) {
			/* error */
			ret_code = HTTP_BAD_REQUEST;
			goto ExitFunction;
		}
		/* read more if necessary entity */
		while (entity_offset + Data_Buf_Size > parser->msg.entity.length &&
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1369,9 +1369,13 @@
 		if (Fp == NULL)
 			return HTTP_INTERNAL_SERVER_ERROR;
 	} else {
+#ifdef UPNP_ENABLE_POST_WRITE
 		Fp = fopen(filename, "wb");
 		if (Fp == NULL)
 			return HTTP_UNAUTHORIZED;
+#else
+		return HTTP_NOT_FOUND;
+#endif
 	}
 	parser->position = POS_ENTITY;
 	do {
```
