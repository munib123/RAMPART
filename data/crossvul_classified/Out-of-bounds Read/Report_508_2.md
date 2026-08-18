# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 508_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `508_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 117-158 of the vulnerable file.

        return;

    free(ptr);
}

/**
 * get next packet in pcap file
 */
u_char *_our_safe_pcap_next(pcap_t *pcap,  struct pcap_pkthdr *pkthdr,
        const char *funcname, const int line, const char *file)
{
    u_char *pktdata = (u_char *)pcap_next(pcap, pkthdr);

    if (pktdata) {
        if (pkthdr->len > MAXPACKET) {
            fprintf(stderr, "safe_pcap_next ERROR: Invalid packet length in %s:%s() line %d: %u is greater than maximum %u\n",
                    file, funcname, line, pkthdr->len, MAXPACKET);
            exit(-1);
        }

        if (pkthdr->len < pkthdr->caplen) {
            fprintf(stderr, "safe_pcap_next ERROR: Invalid packet length in %s:%s() line %d: packet length %u is less than capture length %u\n",
                    file, funcname, line, pkthdr->len, pkthdr->caplen);
            exit(-1);
        }
    }

    return pktdata;
}

/**
 * get next packet in pcap file (extended)
 */
int _our_safe_pcap_next_ex(pcap_t *pcap, struct pcap_pkthdr **pkthdr,
        const u_char **pktdata, const char *funcname,
        const int line, const char *file)
{
    int res = pcap_next_ex(pcap, pkthdr, pktdata);

    if (*pktdata && *pkthdr) {
        if ((*pkthdr)->len > MAXPACKET) {
            fprintf(stderr, "safe_pcap_next_ex ERROR: Invalid packet length in %s:%s() line %d: %u is greater than maximum %u\n",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -134,8 +134,8 @@
             exit(-1);
         }
 
-        if (pkthdr->len < pkthdr->caplen) {
-            fprintf(stderr, "safe_pcap_next ERROR: Invalid packet length in %s:%s() line %d: packet length %u is less than capture length %u\n",
+        if (!pkthdr->len || pkthdr->len < pkthdr->caplen) {
+            fprintf(stderr, "safe_pcap_next ERROR: Invalid packet length in %s:%s() line %d: packet length=%u capture length=%u\n",
                     file, funcname, line, pkthdr->len, pkthdr->caplen);
             exit(-1);
         }
@@ -160,8 +160,8 @@
             exit(-1);
         }
 
-        if ((*pkthdr)->len < (*pkthdr)->caplen) {
-            fprintf(stderr, "safe_pcap_next_ex ERROR: Invalid packet length in %s:%s() line %d: packet length %u is less than capture length %u\n",
+        if (!(*pkthdr)->len || (*pkthdr)->len < (*pkthdr)->caplen) {
+            fprintf(stderr, "safe_pcap_next_ex ERROR: Invalid packet length in %s:%s() line %d: packet length=%u capture length=%u\n",
                     file, funcname, line, (*pkthdr)->len, (*pkthdr)->caplen);
             exit(-1);
         }
```
