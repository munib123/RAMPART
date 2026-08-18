# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4540_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4540_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 610-651 of the vulnerable file.

                    /* Decode the array entry */
                    pItem = *(uint8_t**)iter->pData + iter->pos->data_size * (*size);
                    initialize_pointer_field(pItem, iter);
                    if (!func(&substream, iter->pos, pItem))
                    {
                        status = false;
                        break;
                    }
                    (*size)++;
                }
                pb_close_string_substream(stream, &substream);
                
                return status;
            }
            else
            {
                /* Normal repeated field, i.e. only one item at a time. */
                size_t *size = (size_t*)iter->pSize;
                void *pItem;
                
                (*size)++;
                if (!allocate_field(stream, iter->pData, iter->pos->data_size, *size))
                    return false;
            
                pItem = *(uint8_t**)iter->pData + iter->pos->data_size * (*size - 1);
                initialize_pointer_field(pItem, iter);
                return func(stream, iter->pos, pItem);
            }
            
        default:
            PB_RETURN_ERROR(stream, "invalid field type");
    }
#endif
}

static bool checkreturn decode_callback_field(pb_istream_t *stream, pb_wire_type_t wire_type, pb_field_iterator_t *iter)
{
    pb_callback_t *pCallback = (pb_callback_t*)iter->pData;
    
#ifdef PB_OLD_CALLBACK_STYLE
    void *arg = pCallback->arg;
#else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -627,11 +627,11 @@
                 size_t *size = (size_t*)iter->pSize;
                 void *pItem;
                 
-                (*size)++;
-                if (!allocate_field(stream, iter->pData, iter->pos->data_size, *size))
+                if (!allocate_field(stream, iter->pData, iter->pos->data_size, (size_t)(*size + 1)))
                     return false;
             
-                pItem = *(uint8_t**)iter->pData + iter->pos->data_size * (*size - 1);
+                pItem = *(uint8_t**)iter->pData + iter->pos->data_size * (*size);
+                (*size)++;
                 initialize_pointer_field(pItem, iter);
                 return func(stream, iter->pos, pItem);
             }
```
