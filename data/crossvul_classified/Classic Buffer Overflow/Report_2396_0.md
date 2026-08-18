# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 2396_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2396_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 1531-1571 of the vulnerable file.

            if( !p_block )
                return NULL;

            memcpy( p_block->p_buffer, p_enc_buf->data, p_enc_buf->length );
            schro_buffer_unref( p_enc_buf );

            /* Presence of a Sequence header indicates a seek point */
            if( 0 == p_block->p_buffer[4] )
            {
                p_block->i_flags |= BLOCK_FLAG_TYPE_I;

                if( !p_enc->fmt_out.p_extra ) {
                    const uint8_t eos[] = { 'B','B','C','D',0x10,0,0,0,13,0,0,0,0 };
                    uint32_t len = GetDWBE( p_block->p_buffer + 5 );
                    /* if it hasn't been done so far, stash a copy of the
                     * sequence header for muxers such as ogg */
                    /* The OggDirac spec advises that a Dirac EOS DataUnit
                     * is appended to the sequence header to allow guard
                     * against poor streaming servers */
                    /* XXX, should this be done using the packetizer ? */
                    p_enc->fmt_out.p_extra = malloc( len + sizeof( eos ) );
                    if( !p_enc->fmt_out.p_extra )
                        return NULL;
                    memcpy( p_enc->fmt_out.p_extra, p_block->p_buffer, len );
                    memcpy( (uint8_t*)p_enc->fmt_out.p_extra + len, eos, sizeof( eos ) );
                    SetDWBE( (uint8_t*)p_enc->fmt_out.p_extra + len + sizeof(eos) - 4, len );
                    p_enc->fmt_out.i_extra = len + sizeof( eos );
                }
            }

            if( ReadDiracPictureNumber( &u_pic_num, p_block ) ) {
                block_t *p_dts_block = block_FifoGet( p_sys->p_dts_fifo );
                p_block->i_dts = p_dts_block->i_dts;
                   p_block->i_pts = GetPicturePTS( p_enc, u_pic_num );
                block_Release( p_dts_block );
                block_ChainAppend( &p_output_chain, p_block );
            } else {
                /* End of sequence */
                block_ChainAppend( &p_output_chain, p_block );
            }
            break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1548,6 +1548,10 @@
                      * is appended to the sequence header to allow guard
                      * against poor streaming servers */
                     /* XXX, should this be done using the packetizer ? */
+
+                    if( len > UINT32_MAX - sizeof( eos ) )
+                        return NULL;
+
                     p_enc->fmt_out.p_extra = malloc( len + sizeof( eos ) );
                     if( !p_enc->fmt_out.p_extra )
                         return NULL;
```
