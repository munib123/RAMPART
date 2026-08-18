# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 1504_0
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1504_0`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 1003-1043 of the vulnerable file.

        crm_trace("Ordinary user '%s' cannot access the CIB without any defined ACLs", doc->user);
        free_xml(target);
        target = NULL;
    }

    if(target) {
        *result = target;
    }

    return TRUE;
}

static void
__xml_acl_post_process(xmlNode * xml)
{
    xmlNode *cIter = __xml_first_child(xml);
    xml_private_t *p = xml->_private;

    if(is_set(p->flags, xpf_created)) {
        xmlAttr *xIter = NULL;

        /* Always allow new scaffolding, ie. node with no attributes or only an 'id' */

        for (xIter = crm_first_attr(xml); xIter != NULL; xIter = xIter->next) {
            const char *prop_name = (const char *)xIter->name;

            if (strcmp(prop_name, XML_ATTR_ID) == 0) {
                /* Delay the acl check */
                continue;

            } else if(__xml_acl_check(xml, NULL, xpf_acl_write)) {
                crm_trace("Creation of %s=%s is allowed", crm_element_name(xml), ID(xml));
                break;

            } else {
                char *path = xml_get_path(xml);
                crm_trace("Cannot add new node %s at %s", crm_element_name(xml), path);

                if(xml != xmlDocGetRootElement(xml->doc)) {
                    xmlUnlinkNode(xml);
                    xmlFreeNode(xml);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1020,13 +1020,16 @@
 
     if(is_set(p->flags, xpf_created)) {
         xmlAttr *xIter = NULL;
-
-        /* Always allow new scaffolding, ie. node with no attributes or only an 'id' */
+        char *path = xml_get_path(xml);
+
+        /* Always allow new scaffolding, ie. node with no attributes or only an 'id'
+         * Except in the ACLs section
+         */
 
         for (xIter = crm_first_attr(xml); xIter != NULL; xIter = xIter->next) {
             const char *prop_name = (const char *)xIter->name;
 
-            if (strcmp(prop_name, XML_ATTR_ID) == 0) {
+            if (strcmp(prop_name, XML_ATTR_ID) == 0 && strstr(path, "/"XML_CIB_TAG_ACLS"/") == NULL) {
                 /* Delay the acl check */
                 continue;
 
@@ -1035,7 +1038,6 @@
                 break;
 
             } else {
-                char *path = xml_get_path(xml);
                 crm_trace("Cannot add new node %s at %s", crm_element_name(xml), path);
 
                 if(xml != xmlDocGetRootElement(xml->doc)) {
@@ -1046,6 +1048,7 @@
                 return;
             }
         }
+        free(path);
     }
 
     while (cIter != NULL) {
```
