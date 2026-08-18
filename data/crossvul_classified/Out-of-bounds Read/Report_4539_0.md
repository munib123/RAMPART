# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4539_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4539_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 703-744 of the vulnerable file.

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
                pb_size_t *size = (pb_size_t*)field->pSize;

                if (*size == PB_SIZE_MAX)
                    PB_RETURN_ERROR(stream, "too many array entries");
                
                if (!check_wire_type(wire_type, field))
                    PB_RETURN_ERROR(stream, "wrong wire type");

                (*size)++;
                if (!allocate_field(stream, field->pField, field->data_size, *size))
                    return false;
            
                field->pData = *(char**)field->pField + field->data_size * (*size - 1);
                initialize_pointer_field(field->pData, field);
                return decode_basic_field(stream, field);
            }

        default:
            PB_RETURN_ERROR(stream, "invalid field type");
    }
#endif
}

static bool checkreturn decode_callback_field(pb_istream_t *stream, pb_wire_type_t wire_type, pb_field_iter_t *field)
{
    if (!field->descriptor->field_callback)
        return pb_skip_field(stream, wire_type);

    if (wire_type == PB_WT_STRING)
    {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -720,11 +720,11 @@
                 if (!check_wire_type(wire_type, field))
                     PB_RETURN_ERROR(stream, "wrong wire type");
 
-                (*size)++;
-                if (!allocate_field(stream, field->pField, field->data_size, *size))
+                if (!allocate_field(stream, field->pField, field->data_size, (size_t)(*size + 1)))
                     return false;
             
-                field->pData = *(char**)field->pField + field->data_size * (*size - 1);
+                field->pData = *(char**)field->pField + field->data_size * (*size);
+                (*size)++;
                 initialize_pointer_field(field->pData, field);
                 return decode_basic_field(stream, field);
             }
```
