# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 2394_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2394_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 176-216 of the vulnerable file.

 * p_update has to be locked when calling this function
 *
 * \param p_update pointer to update struct
 * \return true if the update is valid and authenticated
 */
static bool GetUpdateFile( update_t *p_update )
{
    stream_t *p_stream = NULL;
    char *psz_version_line = NULL;
    char *psz_update_data = NULL;

    p_stream = stream_UrlNew( p_update->p_libvlc, UPDATE_VLC_STATUS_URL );
    if( !p_stream )
    {
        msg_Err( p_update->p_libvlc, "Failed to open %s for reading",
                 UPDATE_VLC_STATUS_URL );
        goto error;
    }

    const int64_t i_read = stream_Size( p_stream );
    psz_update_data = malloc( i_read + 1 ); /* terminating '\0' */
    if( !psz_update_data )
        goto error;

    if( stream_Read( p_stream, psz_update_data, i_read ) != i_read )
    {
        msg_Err( p_update->p_libvlc, "Couldn't download update file %s",
                UPDATE_VLC_STATUS_URL );
        goto error;
    }
    psz_update_data[i_read] = '\0';

    stream_Delete( p_stream );
    p_stream = NULL;

    /* first line : version number */
    char *psz_update_data_parser = psz_update_data;
    size_t i_len = strcspn( psz_update_data, "\r\n" );
    psz_update_data_parser += i_len;
    while( *psz_update_data_parser == '\r' || *psz_update_data_parser == '\n' )
        psz_update_data_parser++;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -193,6 +193,13 @@
     }
 
     const int64_t i_read = stream_Size( p_stream );
+
+    if( i_read < 0 || i_read >= UINT16_MAX)
+    {
+        msg_Err(p_update->p_libvlc, "Status file too large");
+        goto error;
+    }
+
     psz_update_data = malloc( i_read + 1 ); /* terminating '\0' */
     if( !psz_update_data )
         goto error;
```
