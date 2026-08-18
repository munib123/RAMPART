# CrossVul Fix Pair: Numeric Errors in c
**Pair ID:** 2201_0
**Vulnerability Class:** Numeric Errors
**CWE:** CWE-189
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2201_0`)

## Vulnerability Information & PoC

## Description
Numeric Errors

## Vulnerable Code
```c
Lines 446-486 of the vulnerable file.

        goto cleanup;
    }
    for (i = 0, last = 0, j = 0, currkvno = key_data[0].key_data_kvno; i < n_key_data; i++) {
        krb5_data *code;
        if (i == n_key_data - 1 || key_data[i + 1].key_data_kvno != currkvno) {
            ret[j] = k5alloc(sizeof(struct berval), &err);
            if (ret[j] == NULL)
                goto cleanup;
            err = asn1_encode_sequence_of_keys(key_data + last,
                                               (krb5_int16)i - last + 1,
                                               mkvno, &code);
            if (err)
                goto cleanup;
            /*CHECK_NULL(ret[j]); */
            ret[j]->bv_len = code->length;
            ret[j]->bv_val = code->data;
            free(code);
            j++;
            last = i + 1;

            currkvno = key_data[i].key_data_kvno;
        }
    }
    ret[num_versions] = NULL;

cleanup:

    free(key_data);
    if (err != 0) {
        if (ret != NULL) {
            for (i = 0; i <= num_versions; i++)
                if (ret[i] != NULL)
                    free (ret[i]);
            free (ret);
            ret = NULL;
        }
    }

    return ret;
}

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -463,7 +463,8 @@
             j++;
             last = i + 1;
 
-            currkvno = key_data[i].key_data_kvno;
+            if (i < n_key_data - 1)
+                currkvno = key_data[i + 1].key_data_kvno;
         }
     }
     ret[num_versions] = NULL;
```
