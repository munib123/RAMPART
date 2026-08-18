# CrossVul Fix Pair: Unchecked Return Value in c
**Pair ID:** 4268_0
**Vulnerability Class:** Unchecked Return Value
**CWE:** CWE-252
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4268_0`)

## Vulnerability Information & PoC

## Description
Unchecked Return Value - Two common programmer assumptions are this function call can never fail and it doesn't matter if this function call fails.

## Vulnerable Code
```c
Lines 344-384 of the vulnerable file.

                outPtr  += len;
                tot_len += len;
            }
        }

        packetSize_ms = tot_len / ( DecControl.API_sampleRate / 1000 );
        tottime += GetHighResolutionTime() - starttime;
        totPackets++;

        /* Write output to file */
#ifdef _SYSTEM_IS_BIG_ENDIAN
        swap_endian( out, tot_len );
#endif
        fwrite( out, sizeof( SKP_int16 ), tot_len, speechOutFile );

        /* Update buffer */
        totBytes = 0;
        for( i = 0; i < MAX_LBRR_DELAY; i++ ) {
            totBytes += nBytesPerPacket[ i + 1 ];
        }
        SKP_memmove( payload, &payload[ nBytesPerPacket[ 0 ] ], totBytes * sizeof( SKP_uint8 ) );
        payloadEnd -= nBytesPerPacket[ 0 ];
        SKP_memmove( nBytesPerPacket, &nBytesPerPacket[ 1 ], MAX_LBRR_DELAY * sizeof( SKP_int16 ) );

        if( !quiet ) {
            fprintf( stderr, "\rPackets decoded:             %d", totPackets );
        }
    }

    /* Empty the recieve buffer */
    for( k = 0; k < MAX_LBRR_DELAY; k++ ) {
        if( nBytesPerPacket[ 0 ] == 0 ) {
            /* Indicate lost packet */
            lost = 1;

            /* Packet loss. Search after FEC in next packets. Should be done in the jitter buffer */
            payloadPtr = payload;
            for( i = 0; i < MAX_LBRR_DELAY; i++ ) {
                if( nBytesPerPacket[ i + 1 ] > 0 ) {
                    starttime = GetHighResolutionTime();
                    SKP_Silk_SDK_search_for_LBRR( payloadPtr, nBytesPerPacket[ i + 1 ], ( i + 1 ), FECpayload, &nBytesFEC );
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -361,6 +361,12 @@
         for( i = 0; i < MAX_LBRR_DELAY; i++ ) {
             totBytes += nBytesPerPacket[ i + 1 ];
         }
+        /* Check if the received totBytes is valid */
+        if (totBytes < 0 || totBytes > sizeof(payload))
+        {
+            fprintf( stderr, "\rPackets decoded:             %d", totPackets );
+            return -1;
+        }
         SKP_memmove( payload, &payload[ nBytesPerPacket[ 0 ] ], totBytes * sizeof( SKP_uint8 ) );
         payloadEnd -= nBytesPerPacket[ 0 ];
         SKP_memmove( nBytesPerPacket, &nBytesPerPacket[ 1 ], MAX_LBRR_DELAY * sizeof( SKP_int16 ) );
@@ -453,6 +459,15 @@
         for( i = 0; i < MAX_LBRR_DELAY; i++ ) {
             totBytes += nBytesPerPacket[ i + 1 ];
         }
+
+        /* Check if the received totBytes is valid */
+        if (totBytes < 0 || totBytes > sizeof(payload))
+        {
+            
+            fprintf( stderr, "\rPackets decoded:              %d", totPackets );
+            return -1;
+        }
+        
         SKP_memmove( payload, &payload[ nBytesPerPacket[ 0 ] ], totBytes * sizeof( SKP_uint8 ) );
         payloadEnd -= nBytesPerPacket[ 0 ];
         SKP_memmove( nBytesPerPacket, &nBytesPerPacket[ 1 ], MAX_LBRR_DELAY * sizeof( SKP_int16 ) );
```
