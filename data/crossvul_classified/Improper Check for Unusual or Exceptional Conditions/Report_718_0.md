# CrossVul Fix Pair: Improper Check for Unusual or Exceptional Conditions in c
**Pair ID:** 718_0
**Vulnerability Class:** Improper Check for Unusual or Exceptional Conditions
**CWE:** CWE-754
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `718_0`)

## Vulnerability Information & PoC

## Description
Improper Check for Unusual or Exceptional Conditions - The programmer may assume that certain events or conditions will never occur or do not need to be worried about, such as low memory conditions, lack of access to resources due to restrictive permis...

## Vulnerable Code
```c
Lines 1764-1804 of the vulnerable file.

    if (index < 0)
    {
        return NULL;
    }

    return get_array_item(array, (size_t)index);
}

static cJSON *get_object_item(const cJSON * const object, const char * const name, const cJSON_bool case_sensitive)
{
    cJSON *current_element = NULL;

    if ((object == NULL) || (name == NULL))
    {
        return NULL;
    }

    current_element = object->child;
    if (case_sensitive)
    {
        while ((current_element != NULL) && (strcmp(name, current_element->string) != 0))
        {
            current_element = current_element->next;
        }
    }
    else
    {
        while ((current_element != NULL) && (case_insensitive_strcmp((const unsigned char*)name, (const unsigned char*)(current_element->string)) != 0))
        {
            current_element = current_element->next;
        }
    }

    return current_element;
}

CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON * const object, const char * const string)
{
    return get_object_item(object, string, false);
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1781,7 +1781,7 @@
     current_element = object->child;
     if (case_sensitive)
     {
-        while ((current_element != NULL) && (strcmp(name, current_element->string) != 0))
+        while ((current_element != NULL) && (current_element->string != NULL) && (strcmp(name, current_element->string) != 0))
         {
             current_element = current_element->next;
         }
@@ -1792,6 +1792,10 @@
         {
             current_element = current_element->next;
         }
+    }
+
+    if ((current_element == NULL) || (current_element->string == NULL)) {
+        return NULL;
     }
 
     return current_element;
```
