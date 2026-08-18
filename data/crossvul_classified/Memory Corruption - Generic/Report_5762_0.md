# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5762_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5762_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 30-70 of the vulnerable file.

#define SE_INT_RXER     0x10
#define SE_INT_MD       0x20
#define SE_INT_PHY      0x40

#define SE_RCTL_RXEN    0x01
#define SE_RCTL_AMUL    0x02
#define SE_RCTL_PRMS    0x04
#define SE_RCTL_BADCRC  0x08
#define SE_RCTL_RSTFIFO 0x10

#define SE_TCTL_TXEN    0x01
#define SE_TCTL_PADEN   0x02
#define SE_TCTL_CRC     0x04
#define SE_TCTL_DUPLEX  0x08

#define TYPE_STELLARIS_ENET "stellaris_enet"
#define STELLARIS_ENET(obj) \
    OBJECT_CHECK(stellaris_enet_state, (obj), TYPE_STELLARIS_ENET)

typedef struct {
    SysBusDevice parent_obj;

    uint32_t ris;
    uint32_t im;
    uint32_t rctl;
    uint32_t tctl;
    uint32_t thr;
    uint32_t mctl;
    uint32_t mdv;
    uint32_t mtxd;
    uint32_t mrxd;
    uint32_t np;
    int tx_fifo_len;
    uint8_t tx_fifo[2048];
    /* Real hardware has a 2k fifo, which works out to be at most 31 packets.
       We implement a full 31 packet fifo.  */
    struct {
        uint8_t data[2048];
        int len;
    } rx[31];
    int rx_fifo_offset;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -47,6 +47,11 @@
     OBJECT_CHECK(stellaris_enet_state, (obj), TYPE_STELLARIS_ENET)
 
 typedef struct {
+    uint8_t data[2048];
+    uint32_t len;
+} StellarisEnetRxFrame;
+
+typedef struct {
     SysBusDevice parent_obj;
 
     uint32_t ris;
@@ -59,21 +64,88 @@
     uint32_t mtxd;
     uint32_t mrxd;
     uint32_t np;
-    int tx_fifo_len;
+    uint32_t tx_fifo_len;
     uint8_t tx_fifo[2048];
     /* Real hardware has a 2k fifo, which works out to be at most 31 packets.
        We implement a full 31 packet fifo.  */
-    struct {
-        uint8_t data[2048];
-        int len;
-    } rx[31];
-    int rx_fifo_offset;
-    int next_packet;
+    StellarisEnetRxFrame rx[31];
+    uint32_t rx_fifo_offset;
+    uint32_t next_packet;
     NICState *nic;
     NICConf conf;
     qemu_irq irq;
     MemoryRegion mmio;
 } stellaris_enet_state;
+
+static const VMStateDescription vmstate_rx_frame = {
+    .name = "stellaris_enet/rx_frame",
+    .version_id = 1,
+    .minimum_version_id = 1,
+    .fields = (VMStateField[]) {
+        VMSTATE_UINT8_ARRAY(data, StellarisEnetRxFrame, 2048),
+        VMSTATE_UINT32(len, StellarisEnetRxFrame),
+        VMSTATE_END_OF_LIST()
+    }
+};
+
+static int stellaris_enet_post_load(void *opaque, int version_id)
+{
+    stellaris_enet_state *s = opaque;
+    int i;
+
+    /* Sanitize inbound state. Note that next_packet is an index but
+     * np is a size; hence their valid upper bounds differ.
+     */
+    if (s->next_packet >= ARRAY_SIZE(s->rx)) {
+        return -1;
+    }
+
+    if (s->np > ARRAY_SIZE(s->rx)) {
+        return -1;
+    }
+
+    for (i = 0; i < ARRAY_SIZE(s->rx); i++) {
+        if (s->rx[i].len > ARRAY_SIZE(s->rx[i].data)) {
+            return -1;
+        }
+    }
+
+    if (s->rx_fifo_offset > ARRAY_SIZE(s->rx[0].data) - 4) {
+        return -1;
+    }
+
+    if (s->tx_fifo_len > ARRAY_SIZE(s->tx_fifo)) {
+        return -1;
+    }
+
+    return 0;
+}
+
+static const VMStateDescription vmstate_stellaris_enet = {
+    .name = "stellaris_enet",
+    .version_id = 2,
+    .minimum_version_id = 2,
+    .post_load = stellaris_enet_post_load,
+    .fields = (VMStateField[]) {
+        VMSTATE_UINT32(ris, stellaris_enet_state),
+        VMSTATE_UINT32(im, stellaris_enet_state),
+        VMSTATE_UINT32(rctl, stellaris_enet_state),
+        VMSTATE_UINT32(tctl, stellaris_enet_state),
+        VMSTATE_UINT32(thr, stellaris_enet_state),
+        VMSTATE_UINT32(mctl, stellaris_enet_state),
+        VMSTATE_UINT32(mdv, stellaris_enet_state),
+        VMSTATE_UINT32(mtxd, stellaris_enet_state),
+        VMSTATE_UINT32(mrxd, stellaris_enet_state),
+        VMSTATE_UINT32(np, stellaris_enet_state),
+        VMSTATE_UINT32(tx_fifo_len, stellaris_enet_state),
+        VMSTATE_UINT8_ARRAY(tx_fifo, stellaris_enet_state, 2048),
+        VMSTATE_STRUCT_ARRAY(rx, stellaris_enet_state, 31, 1,
+                             vmstate_rx_frame, StellarisEnetRxFrame),
+        VMSTATE_UINT32(rx_fifo_offset, stellaris_enet_state),
+        VMSTATE_UINT32(next_packet, stellaris_enet_state),
+        VMSTATE_END_OF_LIST()
+    }
+};
 
 static void stellaris_enet_update(stellaris_enet_state *s)
 {
@@ -379,63 +451,6 @@
     s->tx_fifo_len = 0;
 }
 
-static void stellaris_enet_save(QEMUFile *f, void *opaque)
-{
-    stellaris_enet_state *s = (stellaris_enet_state *)opaque;
-    int i;
-
-    qemu_put_be32(f, s->ris);
-    qemu_put_be32(f, s->im);
-    qemu_put_be32(f, s->rctl);
-    qemu_put_be32(f, s->tctl);
-    qemu_put_be32(f, s->thr);
-    qemu_put_be32(f, s->mctl);
-    qemu_put_be32(f, s->mdv);
-    qemu_put_be32(f, s->mtxd);
-    qemu_put_be32(f, s->mrxd);
-    qemu_put_be32(f, s->np);
-    qemu_put_be32(f, s->tx_fifo_len);
-    qemu_put_buffer(f, s->tx_fifo, sizeof(s->tx_fifo));
-    for (i = 0; i < 31; i++) {
-        qemu_put_be32(f, s->rx[i].len);
-        qemu_put_buffer(f, s->rx[i].data, sizeof(s->rx[i].data));
-
-    }
-    qemu_put_be32(f, s->next_packet);
-    qemu_put_be32(f, s->rx_fifo_offset);
-}
-
-static int stellaris_enet_load(QEMUFile *f, void *opaque, int version_id)
-{
-    stellaris_enet_state *s = (stellaris_enet_state *)opaque;
-    int i;
-
-    if (version_id != 1)
-        return -EINVAL;
-
-    s->ris = qemu_get_be32(f);
-    s->im = qemu_get_be32(f);
-    s->rctl = qemu_get_be32(f);
-    s->tctl = qemu_get_be32(f);
-    s->thr = qemu_get_be32(f);
-    s->mctl = qemu_get_be32(f);
-    s->mdv = qemu_get_be32(f);
-    s->mtxd = qemu_get_be32(f);
-    s->mrxd = qemu_get_be32(f);
-    s->np = qemu_get_be32(f);
-    s->tx_fifo_len = qemu_get_be32(f);
-    qemu_get_buffer(f, s->tx_fifo, sizeof(s->tx_fifo));
-    for (i = 0; i < 31; i++) {
-        s->rx[i].len = qemu_get_be32(f);
-        qemu_get_buffer(f, s->rx[i].data, sizeof(s->rx[i].data));
-
-    }
-    s->next_packet = qemu_get_be32(f);
-    s->rx_fifo_offset = qemu_get_be32(f);
-
-    return 0;
-}
-
 static void stellaris_enet_cleanup(NetClientState *nc)
 {
     stellaris_enet_state *s = qemu_get_nic_opaque(nc);
@@ -467,16 +482,12 @@
     qemu_format_nic_info_str(qemu_get_queue(s->nic), s->conf.macaddr.a);
 
     stellaris_enet_reset(s);
-    register_savevm(dev, "stellaris_enet", -1, 1,
-                    stellaris_enet_save, stellaris_enet_load, s);
     return 0;
 }
 
 static void stellaris_enet_unrealize(DeviceState *dev, Error **errp)
 {
     stellaris_enet_state *s = STELLARIS_ENET(dev);
-
-    unregister_savevm(DEVICE(s), "stellaris_enet", s);
 
     memory_region_destroy(&s->mmio);
 }
@@ -494,6 +505,7 @@
     k->init = stellaris_enet_init;
     dc->unrealize = stellaris_enet_unrealize;
     dc->props = stellaris_enet_properties;
+    dc->vmsd = &vmstate_stellaris_enet;
 }
 
 static const TypeInfo stellaris_enet_info = {
```
