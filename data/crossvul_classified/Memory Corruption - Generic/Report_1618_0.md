# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 1618_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1618_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1232-1272 of the vulnerable file.

static void
vhost_scsi_send_evt(struct vhost_scsi *vs,
		   struct vhost_scsi_tpg *tpg,
		   struct se_lun *lun,
		   u32 event,
		   u32 reason)
{
	struct vhost_scsi_evt *evt;

	evt = vhost_scsi_allocate_evt(vs, event, reason);
	if (!evt)
		return;

	if (tpg && lun) {
		/* TODO: share lun setup code with virtio-scsi.ko */
		/*
		 * Note: evt->event is zeroed when we allocate it and
		 * lun[4-7] need to be zero according to virtio-scsi spec.
		 */
		evt->event.lun[0] = 0x01;
		evt->event.lun[1] = tpg->tport_tpgt & 0xFF;
		if (lun->unpacked_lun >= 256)
			evt->event.lun[2] = lun->unpacked_lun >> 8 | 0x40 ;
		evt->event.lun[3] = lun->unpacked_lun & 0xFF;
	}

	llist_add(&evt->list, &vs->vs_event_list);
	vhost_work_queue(&vs->dev, &vs->vs_event_work);
}

static void vhost_scsi_evt_handle_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						poll.work);
	struct vhost_scsi *vs = container_of(vq->dev, struct vhost_scsi, dev);

	mutex_lock(&vq->mutex);
	if (!vq->private_data)
		goto out;

	if (vs->vs_events_missed)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1249,7 +1249,7 @@
 		 * lun[4-7] need to be zero according to virtio-scsi spec.
 		 */
 		evt->event.lun[0] = 0x01;
-		evt->event.lun[1] = tpg->tport_tpgt & 0xFF;
+		evt->event.lun[1] = tpg->tport_tpgt;
 		if (lun->unpacked_lun >= 256)
 			evt->event.lun[2] = lun->unpacked_lun >> 8 | 0x40 ;
 		evt->event.lun[3] = lun->unpacked_lun & 0xFF;
@@ -2120,12 +2120,12 @@
 			struct vhost_scsi_tport, tport_wwn);
 
 	struct vhost_scsi_tpg *tpg;
-	unsigned long tpgt;
+	u16 tpgt;
 	int ret;
 
 	if (strstr(name, "tpgt_") != name)
 		return ERR_PTR(-EINVAL);
-	if (kstrtoul(name + 5, 10, &tpgt) || tpgt > UINT_MAX)
+	if (kstrtou16(name + 5, 10, &tpgt) || tpgt >= VHOST_SCSI_MAX_TARGET)
 		return ERR_PTR(-EINVAL);
 
 	tpg = kzalloc(sizeof(struct vhost_scsi_tpg), GFP_KERNEL);
```
