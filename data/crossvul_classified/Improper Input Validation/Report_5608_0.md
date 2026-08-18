# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5608_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5608_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 138-178 of the vulnerable file.

    /* Collection timeout */
    dcfg->col_timeout = NOT_SET;

    dcfg->crypto_key = NOT_SET_P;
    dcfg->crypto_key_len = NOT_SET;
    dcfg->crypto_key_add = NOT_SET;
    dcfg->crypto_param_name = NOT_SET_P;
    dcfg->hash_is_enabled = NOT_SET;
    dcfg->hash_enforcement = NOT_SET;
    dcfg->crypto_hash_href_rx = NOT_SET;
    dcfg->crypto_hash_faction_rx = NOT_SET;
    dcfg->crypto_hash_location_rx = NOT_SET;
    dcfg->crypto_hash_iframesrc_rx = NOT_SET;
    dcfg->crypto_hash_framesrc_rx = NOT_SET;
    dcfg->crypto_hash_href_pm = NOT_SET;
    dcfg->crypto_hash_faction_pm = NOT_SET;
    dcfg->crypto_hash_location_pm = NOT_SET;
    dcfg->crypto_hash_iframesrc_pm = NOT_SET;
    dcfg->crypto_hash_framesrc_pm = NOT_SET;


    return dcfg;
}

/**
 * Copies rules between one phase of two configuration contexts,
 * taking exceptions into account.
 */
static void copy_rules_phase(apr_pool_t *mp,
                             apr_array_header_t *parent_phase_arr,
                             apr_array_header_t *child_phase_arr,
                             apr_array_header_t *exceptions_arr)
{
    rule_exception **exceptions;
    msre_rule **rules;
    int i, j;
    int mode = 0;

    rules = (msre_rule **)parent_phase_arr->elts;
    for(i = 0; i < parent_phase_arr->nelts; i++) {
        msre_rule *rule = (msre_rule *)rules[i];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -155,6 +155,9 @@
     dcfg->crypto_hash_iframesrc_pm = NOT_SET;
     dcfg->crypto_hash_framesrc_pm = NOT_SET;
 
+
+    /* xml external entity */
+    dcfg->xml_external_entity = NOT_SET;
 
     return dcfg;
 }
@@ -591,6 +594,10 @@
     merged->crypto_hash_framesrc_pm = (child->crypto_hash_framesrc_pm == NOT_SET
         ? parent->crypto_hash_framesrc_pm : child->crypto_hash_framesrc_pm);
 
+    /* xml external entity */
+    merged->xml_external_entity = (child->xml_external_entity == NOT_SET
+        ? parent->xml_external_entity : child->xml_external_entity);
+
     return merged;
 }
 
@@ -711,6 +718,9 @@
     if (dcfg->crypto_hash_iframesrc_pm == NOT_SET) dcfg->crypto_hash_iframesrc_pm = 0;
     if (dcfg->crypto_hash_framesrc_pm == NOT_SET) dcfg->crypto_hash_framesrc_pm = 0;
 
+    /* xml external entity */
+    if (dcfg->xml_external_entity == NOT_SET) dcfg->xml_external_entity = 0;
+
 }
 
 /**
@@ -2282,9 +2292,35 @@
     return NULL;
 }
 
-
 /**
-* \brief Add SecHash configuration option
+* \brief Add SecXmlExternalEntity configuration option
+*
+* \param cmd Pointer to configuration data
+* \param _dcfg Pointer to directory configuration
+* \param p1 Pointer to configuration option
+*
+* \retval NULL On failure
+* \retval apr_psprintf On Success
+*/
+static const char *cmd_xml_external_entity(cmd_parms *cmd, void *_dcfg, const char *p1)
+{
+    directory_config *dcfg = (directory_config *)_dcfg;
+    if (dcfg == NULL) return NULL;
+
+    if (strcasecmp(p1, "on") == 0)  {
+        dcfg->xml_external_entity = 1;
+    }
+    else if (strcasecmp(p1, "off") == 0)    {
+        dcfg->xml_external_entity = 0;
+    }
+    else return apr_psprintf(cmd->pool, "ModSecurity: Invalid value for SecXmlExternalEntity: %s", p1);
+
+    return NULL;
+}
+
+
+/**
+* \brief Add SecHashEngine configuration option
 *
 * \param cmd Pointer to configuration data
 * \param _dcfg Pointer to directory configuration
@@ -2306,7 +2342,7 @@
         dcfg->hash_is_enabled = HASH_DISABLED;
         dcfg->hash_enforcement = HASH_DISABLED;
     }
-    else return apr_psprintf(cmd->pool, "ModSecurity: Invalid value for SecRuleEngine: %s", p1);
+    else return apr_psprintf(cmd->pool, "ModSecurity: Invalid value for SexHashEngine: %s", p1);
 
     return NULL;
 }
@@ -3223,6 +3259,14 @@
         "On or Off"
     ),
 
+    AP_INIT_TAKE1 (
+        "SecXmlExternalEntity",
+        cmd_xml_external_entity,
+        NULL,
+        CMD_SCOPE_ANY,
+        "On or Off"
+    ),
+
     AP_INIT_FLAG (
         "SecRuleInheritance",
         cmd_rule_inheritance,
```
