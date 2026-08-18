# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5608_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5608_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1-37 of the vulnerable file.

/*
* ModSecurity for Apache 2.x, http://www.modsecurity.org/
* Copyright (c) 2004-2011 Trustwave Holdings, Inc. (http://www.trustwave.com/)
*
* You may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* If any of the files related to licensing are missing or if you have any
* other questions related to licensing please contact Trustwave Holdings, Inc.
* directly using the email address security@modsecurity.org.
*/

#include "msc_xml.h"


/**
 * Initialise XML parser.
 */
int xml_init(modsec_rec *msr, char **error_msg) {
    if (error_msg == NULL) return -1;
    *error_msg = NULL;

    msr->xml = apr_pcalloc(msr->mp, sizeof(xml_data));
    if (msr->xml == NULL) return -1;

    return 1;
}

#if 0
static void xml_receive_sax_error(void *data, const char *msg, ...) {
    modsec_rec *msr = (modsec_rec *)data;
    char message[256];

    if (msr == NULL) return;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -14,16 +14,27 @@
 
 #include "msc_xml.h"
 
+static xmlParserInputBufferPtr
+xml_unload_external_entity(const char *URI, xmlCharEncoding enc)    {
+    return NULL;
+}
+
 
 /**
  * Initialise XML parser.
  */
 int xml_init(modsec_rec *msr, char **error_msg) {
+    xmlParserInputBufferCreateFilenameFunc entity;
+
     if (error_msg == NULL) return -1;
     *error_msg = NULL;
 
     msr->xml = apr_pcalloc(msr->mp, sizeof(xml_data));
     if (msr->xml == NULL) return -1;
+
+    if(msr->txcfg->xml_external_entity == 0)    {
+        entity = xmlParserInputBufferCreateFilenameDefault(xml_unload_external_entity);
+    }
 
     return 1;
 }
```
