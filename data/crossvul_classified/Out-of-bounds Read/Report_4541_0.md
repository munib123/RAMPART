# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4541_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4541_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 638-679 of the vulnerable file.

                        status = false;
                        break;
                    }
                    
                    (*size)++;
                }
                if (!pb_close_string_substream(stream, &substream))
                    return false;
                
                return status;
            }
            else
            {
                /* Normal repeated field, i.e. only one item at a time. */
                pb_size_t *size = (pb_size_t*)iter->pSize;
                void *pItem;
                
                if (*size == PB_SIZE_MAX)
                    PB_RETURN_ERROR(stream, "too many array entries");
                
                (*size)++;
                if (!allocate_field(stream, iter->pData, iter->pos->data_size, *size))
                    return false;
            
                pItem = *(char**)iter->pData + iter->pos->data_size * (*size - 1);
                initialize_pointer_field(pItem, iter);
                return func(stream, iter->pos, pItem);
            }

        default:
            PB_RETURN_ERROR(stream, "invalid field type");
    }
#endif
}

static bool checkreturn decode_callback_field(pb_istream_t *stream, pb_wire_type_t wire_type, pb_field_iter_t *iter)
{
    pb_callback_t *pCallback = (pb_callback_t*)iter->pData;
#ifdef PB_OLD_CALLBACK_STYLE
    void *arg;
#else
    void **arg;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -655,11 +655,11 @@
                 if (*size == PB_SIZE_MAX)
                     PB_RETURN_ERROR(stream, "too many array entries");
                 
-                (*size)++;
-                if (!allocate_field(stream, iter->pData, iter->pos->data_size, *size))
+                if (!allocate_field(stream, iter->pData, iter->pos->data_size, (size_t)(*size + 1)))
                     return false;
             
-                pItem = *(char**)iter->pData + iter->pos->data_size * (*size - 1);
+                pItem = *(char**)iter->pData + iter->pos->data_size * (*size);
+                (*size)++;
                 initialize_pointer_field(pItem, iter);
                 return func(stream, iter->pos, pItem);
             }
```
