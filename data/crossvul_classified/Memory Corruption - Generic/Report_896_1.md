# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 896_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `896_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 7-47 of the vulnerable file.


#include <string.h>

#include "mg_internal.h"
#include "mg_mqtt.h"

static uint16_t getu16(const char *p) {
  const uint8_t *up = (const uint8_t *) p;
  return (up[0] << 8) + up[1];
}

static const char *scanto(const char *p, struct mg_str *s) {
  s->len = getu16(p);
  s->p = p + 2;
  return s->p + s->len;
}

MG_INTERNAL int parse_mqtt(struct mbuf *io, struct mg_mqtt_message *mm) {
  uint8_t header;
  size_t len = 0, len_len = 0;
  const char *p, *end;
  unsigned char lc = 0;
  int cmd;

  if (io->len < 2) return MG_MQTT_ERROR_INCOMPLETE_MSG;
  header = io->buf[0];
  cmd = header >> 4;

  /* decode mqtt variable length */
  len = len_len = 0;
  p = io->buf + 1;
  while ((size_t)(p - io->buf) < io->len) {
    lc = *((const unsigned char *) p++);
    len += (lc & 0x7f) << 7 * len_len;
    len_len++;
    if (!(lc & 0x80)) break;
    if (len_len > 4) return MG_MQTT_ERROR_MALFORMED_MSG;
  }

  end = p + len;
  if (lc & 0x80 || len > (io->len - (p - io->buf))) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -24,7 +24,7 @@
 MG_INTERNAL int parse_mqtt(struct mbuf *io, struct mg_mqtt_message *mm) {
   uint8_t header;
   size_t len = 0, len_len = 0;
-  const char *p, *end;
+  const char *p, *end, *eop = &io->buf[io->len];
   unsigned char lc = 0;
   int cmd;
 
@@ -35,7 +35,7 @@
   /* decode mqtt variable length */
   len = len_len = 0;
   p = io->buf + 1;
-  while ((size_t)(p - io->buf) < io->len) {
+  while (p < eop) {
     lc = *((const unsigned char *) p++);
     len += (lc & 0x7f) << 7 * len_len;
     len_len++;
@@ -44,9 +44,7 @@
   }
 
   end = p + len;
-  if (lc & 0x80 || len > (io->len - (p - io->buf))) {
-    return MG_MQTT_ERROR_INCOMPLETE_MSG;
-  }
+  if (lc & 0x80 || end > eop) return MG_MQTT_ERROR_INCOMPLETE_MSG;
 
   mm->cmd = cmd;
   mm->qos = MG_MQTT_GET_QOS(header);
@@ -100,7 +98,9 @@
     case MG_MQTT_CMD_PUBREL:
     case MG_MQTT_CMD_PUBCOMP:
     case MG_MQTT_CMD_SUBACK:
+      if (end - p < 2) return MG_MQTT_ERROR_MALFORMED_MSG;
       mm->message_id = getu16(p);
+      p += 2;
       break;
     case MG_MQTT_CMD_PUBLISH: {
       p = scanto(p, &mm->topic);
```
