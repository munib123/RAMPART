# CrossVul Fix Pair: Integer Overflow or Wraparound in cpp
**Pair ID:** 291_0
**Vulnerability Class:** Integer Overflow
**CWE:** CWE-190
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `291_0`)

## Vulnerability Information & PoC

## Description
Integer Overflow or Wraparound - An integer overflow or wraparound occurs when an integer value is incremented to a value that is too large to store in the associated representation.

## Vulnerable Code
```cpp
Lines 1475-1525 of the vulnerable file.

            if(r!=0) goto done;
        }
    }
done:;
    cbs->HandleRadiotap( *this, &ohdr, p, caplen);
    //return len + ieee802_11_print(p + len, length - len, caplen - len, pad);
#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT
    handle_80211(p+len, caplen-len);
}

void WifiPacket::handle_prism(const u_char *pc, size_t len)
{
    prism2_pkthdr hdr;

    /* get the fields */
    hdr.host_time 	= EXTRACT_LE_32BITS(pc+32);
    hdr.mac_time 	= EXTRACT_LE_32BITS(pc+44);
    hdr.channel 	= EXTRACT_LE_32BITS(pc+56);
    hdr.rssi 		= EXTRACT_LE_32BITS(pc+68);
    hdr.sq 		= EXTRACT_LE_32BITS(pc+80);
    hdr.signal  	= EXTRACT_LE_32BITS(pc+92);
    hdr.noise   	= EXTRACT_LE_32BITS(pc+104);
    hdr.rate		= EXTRACT_LE_32BITS(pc+116)/2;
    hdr.istx		= EXTRACT_LE_32BITS(pc+128);
    cbs->HandlePrism( *this, &hdr, pc + 144, len - 144);
    handle_80211(pc+144,len-144);
}

///////////////////////////////////////////////////////////////////////////////
///
/// handle_*:
/// handle each of the packet types
///

void WifiPacket::handle_ether(const u_char *ptr, size_t len)
{
#if 0
    ether_hdr_t hdr;

    hdr.da = MAC::ether2MAC(ptr);
    hdr.sa = MAC::ether2MAC(ptr+6);
    hdr.type = EXTRACT_16BITS(ptr + 12);

    ptr += 14;
    len -= 14;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1492,17 +1492,19 @@
     prism2_pkthdr hdr;
 
     /* get the fields */
-    hdr.host_time 	= EXTRACT_LE_32BITS(pc+32);
-    hdr.mac_time 	= EXTRACT_LE_32BITS(pc+44);
-    hdr.channel 	= EXTRACT_LE_32BITS(pc+56);
-    hdr.rssi 		= EXTRACT_LE_32BITS(pc+68);
-    hdr.sq 		= EXTRACT_LE_32BITS(pc+80);
-    hdr.signal  	= EXTRACT_LE_32BITS(pc+92);
-    hdr.noise   	= EXTRACT_LE_32BITS(pc+104);
-    hdr.rate		= EXTRACT_LE_32BITS(pc+116)/2;
-    hdr.istx		= EXTRACT_LE_32BITS(pc+128);
-    cbs->HandlePrism( *this, &hdr, pc + 144, len - 144);
-    handle_80211(pc+144,len-144);
+    if (len>=144){
+        hdr.host_time 	= EXTRACT_LE_32BITS(pc+32);
+        hdr.mac_time 	= EXTRACT_LE_32BITS(pc+44);
+        hdr.channel 	= EXTRACT_LE_32BITS(pc+56);
+        hdr.rssi 		= EXTRACT_LE_32BITS(pc+68);
+        hdr.sq 		= EXTRACT_LE_32BITS(pc+80);
+        hdr.signal  	= EXTRACT_LE_32BITS(pc+92);
+        hdr.noise   	= EXTRACT_LE_32BITS(pc+104);
+        hdr.rate		= EXTRACT_LE_32BITS(pc+116)/2;
+        hdr.istx		= EXTRACT_LE_32BITS(pc+128);
+        cbs->HandlePrism( *this, &hdr, pc + 144, len - 144);
+        handle_80211(pc+144,len-144);
+    }
 }
 
 ///////////////////////////////////////////////////////////////////////////////
@@ -1511,6 +1513,7 @@
 /// handle each of the packet types
 ///
 
+/// 2018-08-02: slg - I'm not sure why this is commented out.
 void WifiPacket::handle_ether(const u_char *ptr, size_t len)
 {
 #if 0
@@ -1715,6 +1718,7 @@
         break;
     default:
 #if 0
+        /// 2018-08-02: slg - I'm also not sure why this is commented out.
 	// try handling it as default IP assuming framing is ethernet 
 	// (this is for testing)
         pkt.handle_ip(packet,header->caplen);
```
