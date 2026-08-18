# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 3568_4
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3568_4`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 1213-1253 of the vulnerable file.

   XML_SetUserData(context->parser, context->context_stack);
   XML_SetElementHandler(context->parser, start_element, end_element);
   XML_SetCharacterDataHandler(context->parser, character_data);
#endif

   rdfa_init_context(context);

#ifdef LIBRDFA_IN_RAPTOR
   if(1) {
     raptor_parser* rdf_parser = (raptor_parser*)context->callback_data;

     /* Optionally forbid internal network and file requests in the
      * XML parser
      */
     raptor_sax2_set_option(context->sax2,
                            RAPTOR_OPTION_NO_NET, NULL,
                            RAPTOR_OPTIONS_GET_NUMERIC(rdf_parser, RAPTOR_OPTION_NO_NET));
     raptor_sax2_set_option(context->sax2,
                            RAPTOR_OPTION_NO_FILE, NULL,
                            RAPTOR_OPTIONS_GET_NUMERIC(rdf_parser, RAPTOR_OPTION_NO_FILE));
     if(rdf_parser->uri_filter)
       raptor_sax2_set_uri_filter(context->sax2, rdf_parser->uri_filter,
                                  rdf_parser->uri_filter_user_data);
   }
   
   context->base_uri=raptor_new_uri(context->sax2->world, (const unsigned char*)context->base);
   raptor_sax2_parse_start(context->sax2, context->base_uri);
#endif

   return rval;
}

static int rdfa_process_doctype(rdfacontext* context, size_t* bytes)
{
   int rval = 0;
   char* doctype_position = 0;
   char* doctype_buffer;
   const char* new_doctype =
      "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML+RDFa 1.0//EN\" "
      "\"http://www.w3.org/MarkUp/DTD/xhtml-rdfa-1.dtd\">";

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1230,6 +1230,9 @@
      raptor_sax2_set_option(context->sax2,
                             RAPTOR_OPTION_NO_FILE, NULL,
                             RAPTOR_OPTIONS_GET_NUMERIC(rdf_parser, RAPTOR_OPTION_NO_FILE));
+     raptor_sax2_set_option(context->sax2,
+                            RAPTOR_OPTION_LOAD_EXTERNAL_ENTITIES, NULL,
+                            RAPTOR_OPTIONS_GET_NUMERIC(rdf_parser, RAPTOR_OPTION_LOAD_EXTERNAL_ENTITIES));
      if(rdf_parser->uri_filter)
        raptor_sax2_set_uri_filter(context->sax2, rdf_parser->uri_filter,
                                   rdf_parser->uri_filter_user_data);
```
