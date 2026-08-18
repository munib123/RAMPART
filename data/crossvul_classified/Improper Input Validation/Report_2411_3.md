# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 2411_3
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2411_3`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 447-487 of the vulnerable file.

                    else
                    if (options.mechanism == ZMQ_PLAIN)
                        memcpy (outpos + outsize, "PLAIN", 5);
                    else
                        memcpy (outpos + outsize, "CURVE", 5);
                    outsize += 20;
                    memset (outpos + outsize, 0, 32);
                    outsize += 32;
                    greeting_size = v3_greeting_size;
                }
            }
        }
    }

    //  Position of the revision field in the greeting.
    const size_t revision_pos = 10;

    //  Is the peer using ZMTP/1.0 with no revision number?
    //  If so, we send and receive rest of identity message
    if (greeting_recv [0] != 0xff || !(greeting_recv [9] & 0x01)) {
        encoder = new (std::nothrow) v1_encoder_t (out_batch_size);
        alloc_assert (encoder);

        decoder = new (std::nothrow) v1_decoder_t (in_batch_size, options.maxmsgsize);
        alloc_assert (decoder);

        //  We have already sent the message header.
        //  Since there is no way to tell the encoder to
        //  skip the message header, we simply throw that
        //  header data away.
        const size_t header_size = options.identity_size + 1 >= 255 ? 10 : 2;
        unsigned char tmp [10], *bufferp = tmp;

        //  Prepare the identity message and load it into encoder.
        //  Then consume bytes we have already sent to the peer.
        const int rc = tx_msg.init_size (options.identity_size);
        zmq_assert (rc == 0);
        memcpy (tx_msg.data (), options.identity, options.identity_size);
        encoder->load_msg (&tx_msg);
        size_t buffer_size = encoder->encode (&bufferp, header_size);
        zmq_assert (buffer_size == header_size);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -464,6 +464,11 @@
     //  Is the peer using ZMTP/1.0 with no revision number?
     //  If so, we send and receive rest of identity message
     if (greeting_recv [0] != 0xff || !(greeting_recv [9] & 0x01)) {
+        if (session->zap_enabled ()) {
+            //  Reject ZMTP 1.0 connections if ZAP is enabled
+            error ();
+            return false;
+        }
         encoder = new (std::nothrow) v1_encoder_t (out_batch_size);
         alloc_assert (encoder);
 
@@ -505,6 +510,11 @@
     }
     else
     if (greeting_recv [revision_pos] == ZMTP_1_0) {
+        if (session->zap_enabled ()) {
+            //  Reject ZMTP 1.0 connections if ZAP is enabled
+            error ();
+            return false;
+        }
         encoder = new (std::nothrow) v1_encoder_t (
             out_batch_size);
         alloc_assert (encoder);
@@ -515,6 +525,11 @@
     }
     else
     if (greeting_recv [revision_pos] == ZMTP_2_0) {
+        if (session->zap_enabled ()) {
+            //  Reject ZMTP 1.0 connections if ZAP is enabled
+            error ();
+            return false;
+        }
         encoder = new (std::nothrow) v2_encoder_t (out_batch_size);
         alloc_assert (encoder);
 
```
