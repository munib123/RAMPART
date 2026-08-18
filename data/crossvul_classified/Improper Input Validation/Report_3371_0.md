# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3371_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3371_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 2252-2292 of the vulnerable file.

}

int dns_packet_is_reply_for(DnsPacket *p, const DnsResourceKey *key) {
        int r;

        assert(p);
        assert(key);

        /* Checks if the specified packet is a reply for the specified
         * key and the specified key is the only one in the question
         * section. */

        if (DNS_PACKET_QR(p) != 1)
                return 0;

        /* Let's unpack the packet, if that hasn't happened yet. */
        r = dns_packet_extract(p);
        if (r < 0)
                return r;

        if (p->question->n_keys != 1)
                return 0;

        return dns_resource_key_equal(p->question->keys[0], key);
}

static const char* const dns_rcode_table[_DNS_RCODE_MAX_DEFINED] = {
        [DNS_RCODE_SUCCESS] = "SUCCESS",
        [DNS_RCODE_FORMERR] = "FORMERR",
        [DNS_RCODE_SERVFAIL] = "SERVFAIL",
        [DNS_RCODE_NXDOMAIN] = "NXDOMAIN",
        [DNS_RCODE_NOTIMP] = "NOTIMP",
        [DNS_RCODE_REFUSED] = "REFUSED",
        [DNS_RCODE_YXDOMAIN] = "YXDOMAIN",
        [DNS_RCODE_YXRRSET] = "YRRSET",
        [DNS_RCODE_NXRRSET] = "NXRRSET",
        [DNS_RCODE_NOTAUTH] = "NOTAUTH",
        [DNS_RCODE_NOTZONE] = "NOTZONE",
        [DNS_RCODE_BADVERS] = "BADVERS",
        [DNS_RCODE_BADKEY] = "BADKEY",
        [DNS_RCODE_BADTIME] = "BADTIME",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2268,6 +2268,9 @@
         r = dns_packet_extract(p);
         if (r < 0)
                 return r;
+
+        if (!p->question)
+                return 0;
 
         if (p->question->n_keys != 1)
                 return 0;
```
