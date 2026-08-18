# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3568_7
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3568_7`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 278-318 of the vulnerable file.

    "wwwCertPassphrase",
    "SSL client certificate passphrase"
  },
  { RAPTOR_OPTION_NO_FILE,
    (raptor_option_area)(RAPTOR_OPTION_AREA_PARSER | RAPTOR_OPTION_AREA_SAX2),
    RAPTOR_OPTION_VALUE_TYPE_BOOL,
    "noFile",
    "Parsers and SAX2 deny internal file requests."
  },
  { RAPTOR_OPTION_WWW_SSL_VERIFY_PEER,
    RAPTOR_OPTION_AREA_PARSER,
    RAPTOR_OPTION_VALUE_TYPE_INT,
    "wwwSslVerifyPeer",
    "SSL verify peer certficate"
  },
  { RAPTOR_OPTION_WWW_SSL_VERIFY_HOST,
    RAPTOR_OPTION_AREA_PARSER,
    RAPTOR_OPTION_VALUE_TYPE_INT,
    "wwwSslVerifyHost",
    "SSL verify host matching"
  }
};


static const char * const raptor_option_uri_prefix = "http://feature.librdf.org/raptor-";
/* NOTE: this is strlen(raptor_option_uri_prefix) */
static const int raptor_option_uri_prefix_len = 33;


static raptor_option_area
raptor_option_get_option_area_for_domain(raptor_domain domain)
{
  raptor_option_area area = RAPTOR_OPTION_AREA_NONE;

  if(domain == RAPTOR_DOMAIN_PARSER) 
    area = RAPTOR_OPTION_AREA_PARSER;
  else if(domain == RAPTOR_DOMAIN_SERIALIZER)
    area = RAPTOR_OPTION_AREA_SERIALIZER;
  else if(domain == RAPTOR_DOMAIN_SAX2)
    area = RAPTOR_OPTION_AREA_SAX2;
  else if(domain == RAPTOR_DOMAIN_XML_WRITER)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -295,6 +295,12 @@
     RAPTOR_OPTION_VALUE_TYPE_INT,
     "wwwSslVerifyHost",
     "SSL verify host matching"
+  },
+  { RAPTOR_OPTION_LOAD_EXTERNAL_ENTITIES,
+    (raptor_option_area)(RAPTOR_OPTION_AREA_PARSER | RAPTOR_OPTION_AREA_SAX2),
+    RAPTOR_OPTION_VALUE_TYPE_BOOL,
+    "loadExternalEntities",
+    "Parsers and SAX2 should load external entities."
   }
 };
 
```
