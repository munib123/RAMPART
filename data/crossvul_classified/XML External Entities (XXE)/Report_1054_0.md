# CrossVul Fix Pair: Improper Restriction of XML External Entity Reference in c
**Pair ID:** 1054_0
**Vulnerability Class:** XML External Entities (XXE)
**CWE:** CWE-611
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1054_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of XML External Entity Reference - XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities.

## Vulnerable Code
```c
Lines 384-424 of the vulnerable file.

static Processor externalParEntInitProcessor;
static Processor entityValueProcessor;
static Processor entityValueInitProcessor;
#endif /* XML_DTD */
static Processor epilogProcessor;
static Processor errorProcessor;
static Processor externalEntityInitProcessor;
static Processor externalEntityInitProcessor2;
static Processor externalEntityInitProcessor3;
static Processor externalEntityContentProcessor;
static Processor internalEntityProcessor;

static enum XML_Error handleUnknownEncoding(XML_Parser parser,
                                            const XML_Char *encodingName);
static enum XML_Error processXmlDecl(XML_Parser parser, int isGeneralTextEntity,
                                     const char *s, const char *next);
static enum XML_Error initializeEncoding(XML_Parser parser);
static enum XML_Error doProlog(XML_Parser parser, const ENCODING *enc,
                               const char *s, const char *end, int tok,
                               const char *next, const char **nextPtr,
                               XML_Bool haveMore);
static enum XML_Error processInternalEntity(XML_Parser parser, ENTITY *entity,
                                            XML_Bool betweenDecl);
static enum XML_Error doContent(XML_Parser parser, int startTagLevel,
                                const ENCODING *enc, const char *start,
                                const char *end, const char **endPtr,
                                XML_Bool haveMore);
static enum XML_Error doCdataSection(XML_Parser parser, const ENCODING *,
                                     const char **startPtr, const char *end,
                                     const char **nextPtr, XML_Bool haveMore);
#ifdef XML_DTD
static enum XML_Error doIgnoreSection(XML_Parser parser, const ENCODING *,
                                      const char **startPtr, const char *end,
                                      const char **nextPtr, XML_Bool haveMore);
#endif /* XML_DTD */

static void freeBindings(XML_Parser parser, BINDING *bindings);
static enum XML_Error storeAtts(XML_Parser parser, const ENCODING *,
                                const char *s, TAG_NAME *tagNamePtr,
                                BINDING **bindingsPtr);
static enum XML_Error addBinding(XML_Parser parser, PREFIX *prefix,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -401,7 +401,7 @@
 static enum XML_Error doProlog(XML_Parser parser, const ENCODING *enc,
                                const char *s, const char *end, int tok,
                                const char *next, const char **nextPtr,
-                               XML_Bool haveMore);
+                               XML_Bool haveMore, XML_Bool allowClosingDoctype);
 static enum XML_Error processInternalEntity(XML_Parser parser, ENTITY *entity,
                                             XML_Bool betweenDecl);
 static enum XML_Error doContent(XML_Parser parser, int startTagLevel,
@@ -4046,7 +4046,7 @@
 
   parser->m_processor = prologProcessor;
   return doProlog(parser, parser->m_encoding, s, end, tok, next, nextPtr,
-                  (XML_Bool)! parser->m_parsingStatus.finalBuffer);
+                  (XML_Bool)! parser->m_parsingStatus.finalBuffer, XML_TRUE);
 }
 
 static enum XML_Error PTRCALL
@@ -4090,12 +4090,13 @@
   const char *next = s;
   int tok = XmlPrologTok(parser->m_encoding, s, end, &next);
   return doProlog(parser, parser->m_encoding, s, end, tok, next, nextPtr,
-                  (XML_Bool)! parser->m_parsingStatus.finalBuffer);
+                  (XML_Bool)! parser->m_parsingStatus.finalBuffer, XML_TRUE);
 }
 
 static enum XML_Error
 doProlog(XML_Parser parser, const ENCODING *enc, const char *s, const char *end,
-         int tok, const char *next, const char **nextPtr, XML_Bool haveMore) {
+         int tok, const char *next, const char **nextPtr, XML_Bool haveMore,
+         XML_Bool allowClosingDoctype) {
 #ifdef XML_DTD
   static const XML_Char externalSubsetName[] = {ASCII_HASH, '\0'};
 #endif /* XML_DTD */
@@ -4271,6 +4272,11 @@
       }
       break;
     case XML_ROLE_DOCTYPE_CLOSE:
+      if (allowClosingDoctype != XML_TRUE) {
+        /* Must not close doctype from within expanded parameter entities */
+        return XML_ERROR_INVALID_TOKEN;
+      }
+
       if (parser->m_doctypeName) {
         parser->m_startDoctypeDeclHandler(
             parser->m_handlerArg, parser->m_doctypeName, parser->m_doctypeSysid,
@@ -5174,7 +5180,7 @@
     int tok
         = XmlPrologTok(parser->m_internalEncoding, textStart, textEnd, &next);
     result = doProlog(parser, parser->m_internalEncoding, textStart, textEnd,
-                      tok, next, &next, XML_FALSE);
+                      tok, next, &next, XML_FALSE, XML_FALSE);
   } else
 #endif /* XML_DTD */
     result = doContent(parser, parser->m_tagLevel, parser->m_internalEncoding,
@@ -5217,7 +5223,7 @@
     int tok
         = XmlPrologTok(parser->m_internalEncoding, textStart, textEnd, &next);
     result = doProlog(parser, parser->m_internalEncoding, textStart, textEnd,
-                      tok, next, &next, XML_FALSE);
+                      tok, next, &next, XML_FALSE, XML_TRUE);
   } else
 #endif /* XML_DTD */
     result = doContent(parser, openEntity->startTagLevel,
@@ -5244,7 +5250,7 @@
     parser->m_processor = prologProcessor;
     tok = XmlPrologTok(parser->m_encoding, s, end, &next);
     return doProlog(parser, parser->m_encoding, s, end, tok, next, nextPtr,
-                    (XML_Bool)! parser->m_parsingStatus.finalBuffer);
+                    (XML_Bool)! parser->m_parsingStatus.finalBuffer, XML_TRUE);
   } else
 #endif /* XML_DTD */
   {
```
