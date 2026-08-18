# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3189_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3189_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 264-304 of the vulnerable file.

                memcpy(&pcap_ph.caplen, &buf[8], 4);
                memcpy(&pcap_ph.len, &buf[12], 4);

                if (swapped == 1) {
                    dbg(3, "Swapping packet header bytes...");
                    pcap_ph.caplen = SWAPLONG(pcap_ph.caplen);
                    pcap_ph.len = SWAPLONG(pcap_ph.len);
                    pcap_ph.ts.tv_sec = SWAPLONG(pcap_ph.ts.tv_sec);
                    pcap_ph.ts.tv_usec = SWAPLONG(pcap_ph.ts.tv_usec);
                }
                printf("%"PRIu64"\t%4"PRIu32"\t\t%4"PRIu32"\t\t%"
                        PRIx32".%"PRIx32,
                        pktcnt, pcap_ph.len, pcap_ph.caplen, 
                        (unsigned int)pcap_ph.ts.tv_sec, (unsigned int)pcap_ph.ts.tv_usec);
                if (pcap_fh.snaplen < pcap_ph.caplen) {
                    caplentoobig = 1;
                }
                caplen = pcap_ph.caplen;
            }

            /* check to make sure timestamps don't go backwards */
            if (last_sec > 0 && last_usec > 0) {
                if ((pcap_ph.ts.tv_sec == last_sec) ? 
                        (pcap_ph.ts.tv_usec < last_usec) : 
                        (pcap_ph.ts.tv_sec < last_sec)) {
                    backwards = 1;
                }
            }
            if (pkthdrlen == sizeof(pcap_patched_ph)) {
                last_sec = pcap_patched_ph.ts.tv_sec;
                last_usec = pcap_patched_ph.ts.tv_usec;
            } else {
                last_sec = pcap_ph.ts.tv_sec;
                last_usec = pcap_ph.ts.tv_usec;
            }

            /* read the frame */
            if ((ret = read(fd, &buf, caplen)) != caplen) {
                if (ret < 0) {
                    printf("Error reading file: %s: %s\n", argv[i], strerror(errno));
                } else {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -281,6 +281,15 @@
                 caplen = pcap_ph.caplen;
             }
 
+            if (caplentoobig) {
+                printf("\n\nCapture file appears to be damaged or corrupt.\n"
+                        "Contains packet of size %u, bigger than snap length %u\n",
+                        caplen, pcap_fh.snaplen);
+
+                close(fd);
+                break;
+            }
+
             /* check to make sure timestamps don't go backwards */
             if (last_sec > 0 && last_usec > 0) {
                 if ((pcap_ph.ts.tv_sec == last_sec) ? 
@@ -306,7 +315,7 @@
                 }
 
                 close(fd);
-                continue;
+                break;
             }
 
             /* print the frame checksum */
```
