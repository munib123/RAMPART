# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4359_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4359_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 447-488 of the vulnerable file.

                if (substream.bytes_left != 0)
                    PB_RETURN_ERROR(stream, "array overflow");
                if (!pb_close_string_substream(stream, &substream))
                    return false;

                return status;
            }
            else
            {
                /* Repeated field */
                pb_size_t *size = (pb_size_t*)iter->pSize;
                char *pItem = (char*)iter->pData + iter->pos->data_size * (*size);

                if ((*size)++ >= iter->pos->array_size)
                    PB_RETURN_ERROR(stream, "array overflow");

                return func(stream, iter->pos, pItem);
            }

        case PB_HTYPE_ONEOF:
            *(pb_size_t*)iter->pSize = iter->pos->tag;
            if (PB_LTYPE(type) == PB_LTYPE_SUBMESSAGE)
            {
                /* We memset to zero so that any callbacks are set to NULL.
                 * Then set any default values. */
                memset(iter->pData, 0, iter->pos->data_size);
                pb_message_set_to_defaults((const pb_field_t*)iter->pos->ptr, iter->pData);
            }
            return func(stream, iter->pos, iter->pData);

        default:
            PB_RETURN_ERROR(stream, "invalid field type");
    }
}

#ifdef PB_ENABLE_MALLOC
/* Allocate storage for the field and store the pointer at iter->pData.
 * array_size is the number of entries to reserve in an array.
 * Zero size is not allowed, use pb_free() for releasing.
 */
static bool checkreturn allocate_field(pb_istream_t *stream, void *pData, size_t data_size, size_t array_size)
{    
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -464,14 +464,17 @@
             }
 
         case PB_HTYPE_ONEOF:
-            *(pb_size_t*)iter->pSize = iter->pos->tag;
-            if (PB_LTYPE(type) == PB_LTYPE_SUBMESSAGE)
+            if (PB_LTYPE(type) == PB_LTYPE_SUBMESSAGE &&
+                *(pb_size_t*)iter->pSize != iter->pos->tag)
             {
                 /* We memset to zero so that any callbacks are set to NULL.
-                 * Then set any default values. */
+                 * This is because the callbacks might otherwise have values
+                 * from some other union field. */
                 memset(iter->pData, 0, iter->pos->data_size);
                 pb_message_set_to_defaults((const pb_field_t*)iter->pos->ptr, iter->pData);
             }
+            *(pb_size_t*)iter->pSize = iter->pos->tag;
+
             return func(stream, iter->pos, iter->pData);
 
         default:
```
