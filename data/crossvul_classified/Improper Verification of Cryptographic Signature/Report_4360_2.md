# CrossVul Fix Pair: Improper Verification of Cryptographic Signature in python
**Pair ID:** 4360_2
**Vulnerability Class:** Improper Verification of Cryptographic Signature
**CWE:** CWE-347
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4360_2`)

## Vulnerability Information & PoC

## Description
Improper Verification of Cryptographic Signature - The product does not verify, or incorrectly verifies, the cryptographic signature for data.

## Vulnerable Code
```python
Lines 296-336 of the vulnerable file.

    _packer = JWT()
    _body = _packer.unpack(_jws).payload()

    if "keyjar" in kwargs:
        try:
            if _body["iss"] not in kwargs["keyjar"]:
                raise ValueError("Unknown issuer")
        except KeyError:
            raise MissingRequiredAttribute("iss")

    if _jwe is not None:
        # Use the original encrypted token to set correct headers
        idt = IdToken().from_jwt(str(instance["id_token"]), **args)
    else:
        idt = IdToken().from_jwt(_jws, **args)
    if not idt.verify(**kwargs):
        raise VerificationError("Could not verify id_token", idt)

    if check_hash:
        _alg = idt.jws_header["alg"]
        # What if _alg == 'none'

        hfunc = "HS" + _alg[-3:]

        if "access_token" in instance:
            if "at_hash" not in idt:
                raise MissingRequiredAttribute("Missing at_hash property", idt)
            if idt["at_hash"] != jws.left_hash(instance["access_token"], hfunc):
                raise AtHashError("Failed to verify access_token hash", idt)

        if "code" in instance:
            if "c_hash" not in idt:
                raise MissingRequiredAttribute("Missing c_hash property", idt)
            if idt["c_hash"] != jws.left_hash(instance["code"], hfunc):
                raise CHashError("Failed to verify code hash", idt)

    return idt


# -----------------------------------------------------------------------------

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -313,17 +313,19 @@
 
     if check_hash:
         _alg = idt.jws_header["alg"]
-        # What if _alg == 'none'
-
-        hfunc = "HS" + _alg[-3:]
-
-        if "access_token" in instance:
+        if _alg != "none":
+            hfunc = "HS" + _alg[-3:]
+        else:
+            # This is allowed only for `code` and it needs to be checked by a Client
+            hfunc = None
+
+        if "access_token" in instance and hfunc is not None:
             if "at_hash" not in idt:
                 raise MissingRequiredAttribute("Missing at_hash property", idt)
             if idt["at_hash"] != jws.left_hash(instance["access_token"], hfunc):
                 raise AtHashError("Failed to verify access_token hash", idt)
 
-        if "code" in instance:
+        if "code" in instance and hfunc is not None:
             if "c_hash" not in idt:
                 raise MissingRequiredAttribute("Missing c_hash property", idt)
             if idt["c_hash"] != jws.left_hash(instance["code"], hfunc):
@@ -780,6 +782,11 @@
         else:
             if (_iat + _storage_time) < (_now - _skew):
                 raise IATError("Issued too long ago")
+            if _now < (_iat - _skew):
+                raise IATError("Issued in the future")
+
+        if _exp < _iat:
+            raise EXPError("Invalid expiration time")
 
         return True
 
```
