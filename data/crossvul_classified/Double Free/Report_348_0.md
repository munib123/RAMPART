# CrossVul Fix Pair: Double Free in c
**Pair ID:** 348_0
**Vulnerability Class:** Double Free
**CWE:** CWE-415
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `348_0`)

## Vulnerability Information & PoC

## Description
Double Free - When a program calls free() twice with the same argument, the program's memory management data structures become corrupted.

## Vulnerable Code
```c
Lines 777-817 of the vulnerable file.

	obj_info->path.count = CAC_MAX_SIZE-1; /* read something from the object */
	obj_info->id.value[0] = ((*entry)->fd >> 8) & 0xff;
	obj_info->id.value[1] = (*entry)->fd & 0xff;
	obj_info->id.len = 2;
	strncpy(obj_info->app_label, (*entry)->name, SC_PKCS15_MAX_LABEL_SIZE-1);
	*entry = list_iterator_next(list);
	return SC_SUCCESS;
}

static int cac_get_serial_nr_from_CUID(sc_card_t* card, sc_serial_number_t* serial)
{
	cac_private_data_t * priv = CAC_DATA(card);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
        if (card->serialnr.len)   {
                *serial = card->serialnr;
                SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
        }
	if (priv->cac_id_len) {
		serial->len = MIN(priv->cac_id_len, SC_MAX_SERIALNR);
		memcpy(serial->value, priv->cac_id, priv->cac_id_len);
		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_FILE_NOT_FOUND);
}

static int cac_get_ACA_path(sc_card_t *card, sc_path_t *path)
{
	cac_private_data_t * priv = CAC_DATA(card);

	SC_FUNC_CALLED(card->ctx, SC_LOG_DEBUG_NORMAL);
	if (priv->aca_path) {
		*path = *priv->aca_path;
	}
	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
}

static int cac_card_ctl(sc_card_t *card, unsigned long cmd, void *ptr)
{
	cac_private_data_t * priv = CAC_DATA(card);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -794,7 +794,7 @@
         }
 	if (priv->cac_id_len) {
 		serial->len = MIN(priv->cac_id_len, SC_MAX_SERIALNR);
-		memcpy(serial->value, priv->cac_id, priv->cac_id_len);
+		memcpy(serial->value, priv->cac_id, serial->len);
 		SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_SUCCESS);
 	}
 	SC_FUNC_RETURN(card->ctx, SC_LOG_DEBUG_NORMAL, SC_ERROR_FILE_NOT_FOUND);
```
