# CrossVul Fix Pair: Improper Authentication in python
**Pair ID:** 650_1
**Vulnerability Class:** Improper Authentication - Generic
**CWE:** CWE-287
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `650_1`)

## Vulnerability Information & PoC

## Description
Improper Authentication - When an actor claims to have a given identity, the product does not prove or insufficiently proves that the claim is correct.

## Vulnerable Code
```python
Lines 32-72 of the vulnerable file.

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes

import paramiko
from paramiko import util
from paramiko.auth_handler import AuthHandler
from paramiko.ssh_gss import GSSAuth
from paramiko.channel import Channel
from paramiko.common import (
    xffffffff, cMSG_CHANNEL_OPEN, cMSG_IGNORE, cMSG_GLOBAL_REQUEST, DEBUG,
    MSG_KEXINIT, MSG_IGNORE, MSG_DISCONNECT, MSG_DEBUG, ERROR, WARNING,
    cMSG_UNIMPLEMENTED, INFO, cMSG_KEXINIT, cMSG_NEWKEYS, MSG_NEWKEYS,
    cMSG_REQUEST_SUCCESS, cMSG_REQUEST_FAILURE, CONNECTION_FAILED_CODE,
    OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, OPEN_SUCCEEDED,
    cMSG_CHANNEL_OPEN_FAILURE, cMSG_CHANNEL_OPEN_SUCCESS, MSG_GLOBAL_REQUEST,
    MSG_REQUEST_SUCCESS, MSG_REQUEST_FAILURE, MSG_CHANNEL_OPEN_SUCCESS,
    MSG_CHANNEL_OPEN_FAILURE, MSG_CHANNEL_OPEN, MSG_CHANNEL_SUCCESS,
    MSG_CHANNEL_FAILURE, MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA,
    MSG_CHANNEL_WINDOW_ADJUST, MSG_CHANNEL_REQUEST, MSG_CHANNEL_EOF,
    MSG_CHANNEL_CLOSE, MIN_WINDOW_SIZE, MIN_PACKET_SIZE, MAX_WINDOW_SIZE,
    DEFAULT_WINDOW_SIZE, DEFAULT_MAX_PACKET_SIZE,
)
from paramiko.compress import ZlibCompressor, ZlibDecompressor
from paramiko.dsskey import DSSKey
from paramiko.kex_gex import KexGex, KexGexSHA256
from paramiko.kex_group1 import KexGroup1
from paramiko.kex_group14 import KexGroup14
from paramiko.kex_gss import KexGSSGex, KexGSSGroup1, KexGSSGroup14
from paramiko.message import Message
from paramiko.packet import Packetizer, NeedRekeyException
from paramiko.primes import ModulusPack
from paramiko.py3compat import string_types, long, byte_ord, b, input, PY2
from paramiko.rsakey import RSAKey
from paramiko.ecdsakey import ECDSAKey
from paramiko.server import ServerInterface
from paramiko.sftp_client import SFTPClient
from paramiko.ssh_exception import (
    SSHException, BadAuthenticationType, ChannelException, ProxyCommandFailure,
)
from paramiko.util import retry_on_signal, ClosingContextManager, clamp_value

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -49,7 +49,7 @@
     MSG_CHANNEL_FAILURE, MSG_CHANNEL_DATA, MSG_CHANNEL_EXTENDED_DATA,
     MSG_CHANNEL_WINDOW_ADJUST, MSG_CHANNEL_REQUEST, MSG_CHANNEL_EOF,
     MSG_CHANNEL_CLOSE, MIN_WINDOW_SIZE, MIN_PACKET_SIZE, MAX_WINDOW_SIZE,
-    DEFAULT_WINDOW_SIZE, DEFAULT_MAX_PACKET_SIZE,
+    DEFAULT_WINDOW_SIZE, DEFAULT_MAX_PACKET_SIZE, HIGHEST_USERAUTH_MESSAGE_ID,
 )
 from paramiko.compress import ZlibCompressor, ZlibDecompressor
 from paramiko.dsskey import DSSKey
@@ -1760,6 +1760,43 @@
             max_packet_size = self.default_max_packet_size
         return clamp_value(MIN_PACKET_SIZE, max_packet_size, MAX_WINDOW_SIZE)
 
+    def _ensure_authed(self, ptype, message):
+        """
+        Checks message type against current auth state.
+
+        If server mode, and auth has not succeeded, and the message is of a
+        post-auth type (channel open or global request) an appropriate error
+        response Message is crafted and returned to caller for sending.
+
+        Otherwise (client mode, authed, or pre-auth message) returns None.
+        """
+        if (
+            not self.server_mode
+            or ptype <= HIGHEST_USERAUTH_MESSAGE_ID
+            or self.is_authenticated()
+        ):
+            return None
+        # WELP. We must be dealing with someone trying to do non-auth things
+        # without being authed. Tell them off, based on message class.
+        reply = Message()
+        # Global requests have no details, just failure.
+        if ptype == MSG_GLOBAL_REQUEST:
+            reply.add_byte(cMSG_REQUEST_FAILURE)
+        # Channel opens let us reject w/ a specific type + message.
+        elif ptype == MSG_CHANNEL_OPEN:
+            kind = message.get_text()
+            chanid = message.get_int()
+            reply.add_byte(cMSG_CHANNEL_OPEN_FAILURE)
+            reply.add_int(chanid)
+            reply.add_int(OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)
+            reply.add_string('')
+            reply.add_string('en')
+        # NOTE: Post-open channel messages do not need checking; the above will
+        # reject attemps to open channels, meaning that even if a malicious
+        # user tries to send a MSG_CHANNEL_REQUEST, it will simply fall under
+        # the logic that handles unknown channel IDs (as the channel list will
+        # be empty.)
+        return reply
 
     def run(self):
         # (use the exposed "run" method, because if we specify a thread target
@@ -1820,7 +1857,11 @@
                             continue
 
                     if ptype in self._handler_table:
-                        self._handler_table[ptype](self, m)
+                        error_msg = self._ensure_authed(ptype, m)
+                        if error_msg:
+                            self._send_message(error_msg)
+                        else:
+                            self._handler_table[ptype](self, m)
                     elif ptype in self._channel_handler_table:
                         chanid = m.get_int()
                         chan = self._channels.get(chanid)
```
