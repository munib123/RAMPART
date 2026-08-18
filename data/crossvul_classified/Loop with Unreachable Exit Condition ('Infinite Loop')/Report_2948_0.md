# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 2948_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2948_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 2232-2272 of the vulnerable file.

 * xmlPushInput:
 * @ctxt:  an XML parser context
 * @input:  an XML parser input fragment (entity, XML fragment ...).
 *
 * xmlPushInput: switch to a new input stream which is stacked on top
 *               of the previous one(s).
 * Returns -1 in case of error or the index in the input stack
 */
int
xmlPushInput(xmlParserCtxtPtr ctxt, xmlParserInputPtr input) {
    int ret;
    if (input == NULL) return(-1);

    if (xmlParserDebugEntities) {
	if ((ctxt->input != NULL) && (ctxt->input->filename))
	    xmlGenericError(xmlGenericErrorContext,
		    "%s(%d): ", ctxt->input->filename,
		    ctxt->input->line);
	xmlGenericError(xmlGenericErrorContext,
		"Pushing input %d : %.30s\n", ctxt->inputNr+1, input->cur);
    }
    ret = inputPush(ctxt, input);
    if (ctxt->instate == XML_PARSER_EOF)
        return(-1);
    GROW;
    return(ret);
}

/**
 * xmlParseCharRef:
 * @ctxt:  an XML parser context
 *
 * parse Reference declarations
 *
 * [66] CharRef ::= '&#' [0-9]+ ';' |
 *                  '&#x' [0-9a-fA-F]+ ';'
 *
 * [ WFC: Legal Character ]
 * Characters referred to using character references must match the
 * production for Char.
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2250,6 +2250,13 @@
 	xmlGenericError(xmlGenericErrorContext,
 		"Pushing input %d : %.30s\n", ctxt->inputNr+1, input->cur);
     }
+    if (((ctxt->inputNr > 40) && ((ctxt->options & XML_PARSE_HUGE) == 0)) ||
+        (ctxt->inputNr > 1024)) {
+        xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, NULL);
+        while (ctxt->inputNr > 1)
+            xmlFreeInputStream(inputPop(ctxt));
+	return(-1);
+    }
     ret = inputPush(ctxt, input);
     if (ctxt->instate == XML_PARSER_EOF)
         return(-1);
@@ -7916,8 +7923,10 @@
 		return;
 
 	    input = xmlNewEntityInputStream(ctxt, entity);
-	    if (xmlPushInput(ctxt, input) < 0)
+	    if (xmlPushInput(ctxt, input) < 0) {
+                xmlFreeInputStream(input);
 		return;
+            }
 
 	    if (entity->etype == XML_EXTERNAL_PARAMETER_ENTITY) {
                 /*
```
