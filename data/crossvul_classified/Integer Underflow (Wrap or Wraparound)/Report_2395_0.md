# CrossVul Fix Pair: Integer Underflow (Wrap or Wraparound) in c
**Pair ID:** 2395_0
**Vulnerability Class:** Integer Underflow (Wrap or Wraparound)
**CWE:** CWE-191
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2395_0`)

## Vulnerability Information & PoC

## Description
Integer Underflow (Wrap or Wraparound) - This can happen in signed and unsigned cases.

## Vulnerable Code
```c
Lines 2841-2881 of the vulnerable file.

             p_box->data.p_skcr->i_decr );
#endif

    MP4_READBOX_EXIT( 1 );
}

static int MP4_ReadBox_drms( stream_t *p_stream, MP4_Box_t *p_box )
{
    VLC_UNUSED(p_box);
    /* ATOMs 'user', 'key', 'iviv', and 'priv' will be skipped,
     * so unless data decrypt itself by magic, there will be no playback,
     * but we never know... */
    msg_Warn( p_stream, "DRM protected streams are not supported." );
    return 1;
}

static int MP4_ReadBox_String( stream_t *p_stream, MP4_Box_t *p_box )
{
    MP4_READBOX_ENTER( MP4_Box_data_string_t );

    p_box->data.p_string->psz_text = malloc( p_box->i_size + 1 - 8 ); /* +\0, -name, -size */
    if( p_box->data.p_string->psz_text == NULL )
        MP4_READBOX_EXIT( 0 );

    memcpy( p_box->data.p_string->psz_text, p_peek, p_box->i_size - 8 );
    p_box->data.p_string->psz_text[p_box->i_size - 8] = '\0';

#ifdef MP4_VERBOSE
        msg_Dbg( p_stream, "read box: \"%4.4s\" text=`%s'", (char *) & p_box->i_type,
                 p_box->data.p_string->psz_text );
#endif
    MP4_READBOX_EXIT( 1 );
}

static void MP4_FreeBox_String( MP4_Box_t *p_box )
{
    FREENULL( p_box->data.p_string->psz_text );
}

static int MP4_ReadBox_Binary( stream_t *p_stream, MP4_Box_t *p_box )
{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2857,6 +2857,9 @@
 static int MP4_ReadBox_String( stream_t *p_stream, MP4_Box_t *p_box )
 {
     MP4_READBOX_ENTER( MP4_Box_data_string_t );
+
+    if( p_box->i_size < 8 || p_box->i_size > SIZE_MAX )
+        MP4_READBOX_EXIT( 0 );
 
     p_box->data.p_string->psz_text = malloc( p_box->i_size + 1 - 8 ); /* +\0, -name, -size */
     if( p_box->data.p_string->psz_text == NULL )
```
