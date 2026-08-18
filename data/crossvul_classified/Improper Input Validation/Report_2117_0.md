# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 2117_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2117_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 331-387 of the vulnerable file.

}

static void cm_set_private_data(struct cm_id_private *cm_id_priv,
				 void *private_data, u8 private_data_len)
{
	if (cm_id_priv->private_data && cm_id_priv->private_data_len)
		kfree(cm_id_priv->private_data);

	cm_id_priv->private_data = private_data;
	cm_id_priv->private_data_len = private_data_len;
}

static void cm_init_av_for_response(struct cm_port *port, struct ib_wc *wc,
				    struct ib_grh *grh, struct cm_av *av)
{
	av->port = port;
	av->pkey_index = wc->pkey_index;
	ib_init_ah_from_wc(port->cm_dev->ib_device, port->port_num, wc,
			   grh, &av->ah_attr);
}

int ib_update_cm_av(struct ib_cm_id *id, const u8 *smac, const u8 *alt_smac)
{
	struct cm_id_private *cm_id_priv;

	cm_id_priv = container_of(id, struct cm_id_private, id);

	if (smac != NULL)
		memcpy(cm_id_priv->av.smac, smac, sizeof(cm_id_priv->av.smac));

	if (alt_smac != NULL)
		memcpy(cm_id_priv->alt_av.smac, alt_smac,
		       sizeof(cm_id_priv->alt_av.smac));

	return 0;
}
EXPORT_SYMBOL(ib_update_cm_av);

static int cm_init_av_by_path(struct ib_sa_path_rec *path, struct cm_av *av)
{
	struct cm_device *cm_dev;
	struct cm_port *port = NULL;
	unsigned long flags;
	int ret;
	u8 p;

	read_lock_irqsave(&cm.device_lock, flags);
	list_for_each_entry(cm_dev, &cm.device_list, list) {
		if (!ib_find_cached_gid(cm_dev->ib_device, &path->sgid,
					&p, NULL)) {
			port = cm_dev->port[p-1];
			break;
		}
	}
	read_unlock_irqrestore(&cm.device_lock, flags);

	if (!port)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -348,23 +348,6 @@
 	ib_init_ah_from_wc(port->cm_dev->ib_device, port->port_num, wc,
 			   grh, &av->ah_attr);
 }
-
-int ib_update_cm_av(struct ib_cm_id *id, const u8 *smac, const u8 *alt_smac)
-{
-	struct cm_id_private *cm_id_priv;
-
-	cm_id_priv = container_of(id, struct cm_id_private, id);
-
-	if (smac != NULL)
-		memcpy(cm_id_priv->av.smac, smac, sizeof(cm_id_priv->av.smac));
-
-	if (alt_smac != NULL)
-		memcpy(cm_id_priv->alt_av.smac, alt_smac,
-		       sizeof(cm_id_priv->alt_av.smac));
-
-	return 0;
-}
-EXPORT_SYMBOL(ib_update_cm_av);
 
 static int cm_init_av_by_path(struct ib_sa_path_rec *path, struct cm_av *av)
 {
```
