# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 3006_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3006_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 462-502 of the vulnerable file.

    MD5 md5;
    md5.encodeDataIncrementally(
	pad_or_truncate_password_V4(password).c_str(), key_bytes);
    MD5::Digest digest;
    iterate_md5_digest(md5, digest, ((data.getR() >= 3) ? 50 : 0));
    memcpy(key, digest, OU_key_bytes_V4);
}

static std::string
compute_O_value(std::string const& user_password,
		std::string const& owner_password,
		QPDF::EncryptionData const& data)
{
    // Algorithm 3.3 from the PDF 1.7 Reference Manual

    unsigned char O_key[OU_key_bytes_V4];
    compute_O_rc4_key(user_password, owner_password, data, O_key);

    char upass[key_bytes];
    pad_or_truncate_password_V4(user_password, upass);
    iterate_rc4(QUtil::unsigned_char_pointer(upass), key_bytes,
		O_key, data.getLengthBytes(),
                (data.getR() >= 3) ? 20 : 1, false);
    return std::string(upass, key_bytes);
}

static
std::string
compute_U_value_R2(std::string const& user_password,
		   QPDF::EncryptionData const& data)
{
    // Algorithm 3.4 from the PDF 1.7 Reference Manual

    std::string k1 = QPDF::compute_encryption_key(user_password, data);
    char udata[key_bytes];
    pad_or_truncate_password_V4("", udata);
    iterate_rc4(QUtil::unsigned_char_pointer(udata), key_bytes,
		QUtil::unsigned_char_pointer(k1),
                data.getLengthBytes(), 1, false);
    return std::string(udata, key_bytes);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -479,6 +479,8 @@
 
     char upass[key_bytes];
     pad_or_truncate_password_V4(user_password, upass);
+    std::string k1(reinterpret_cast<char*>(O_key), OU_key_bytes_V4);
+    pad_short_parameter(k1, data.getLengthBytes());
     iterate_rc4(QUtil::unsigned_char_pointer(upass), key_bytes,
 		O_key, data.getLengthBytes(),
                 (data.getR() >= 3) ? 20 : 1, false);
@@ -495,6 +497,7 @@
     std::string k1 = QPDF::compute_encryption_key(user_password, data);
     char udata[key_bytes];
     pad_or_truncate_password_V4("", udata);
+    pad_short_parameter(k1, data.getLengthBytes());
     iterate_rc4(QUtil::unsigned_char_pointer(udata), key_bytes,
 		QUtil::unsigned_char_pointer(k1),
                 data.getLengthBytes(), 1, false);
@@ -516,6 +519,7 @@
                                 data.getId1().length());
     MD5::Digest digest;
     md5.digest(digest);
+    pad_short_parameter(k1, data.getLengthBytes());
     iterate_rc4(digest, sizeof(MD5::Digest),
 		QUtil::unsigned_char_pointer(k1),
                 data.getLengthBytes(), 20, false);
@@ -591,7 +595,10 @@
     compute_O_rc4_key(user_password, owner_password, data, key);
     unsigned char O_data[key_bytes];
     memcpy(O_data, QUtil::unsigned_char_pointer(data.getO()), key_bytes);
-    iterate_rc4(O_data, key_bytes, key, data.getLengthBytes(),
+    std::string k1(reinterpret_cast<char*>(key), OU_key_bytes_V4);
+    pad_short_parameter(k1, data.getLengthBytes());
+    iterate_rc4(O_data, key_bytes, QUtil::unsigned_char_pointer(k1),
+                data.getLengthBytes(),
                 (data.getR() >= 3) ? 20 : 1, true);
     std::string new_user_password =
         std::string(reinterpret_cast<char*>(O_data), key_bytes);
@@ -886,6 +893,7 @@
 
     if (V < 5)
     {
+        // These must be exactly the right number of bytes.
         pad_short_parameter(O, key_bytes);
         pad_short_parameter(U, key_bytes);
         if (! ((O.length() == key_bytes) && (U.length() == key_bytes)))
@@ -913,24 +921,12 @@
         UE = encryption_dict.getKey("/UE").getStringValue();
         Perms = encryption_dict.getKey("/Perms").getStringValue();
 
+        // These may be longer than the minimum number of bytes.
         pad_short_parameter(O, OU_key_bytes_V5);
         pad_short_parameter(U, OU_key_bytes_V5);
         pad_short_parameter(OE, OUE_key_bytes_V5);
         pad_short_parameter(UE, OUE_key_bytes_V5);
         pad_short_parameter(Perms, Perms_key_bytes_V5);
-        if ((O.length() < OU_key_bytes_V5) ||
-            (U.length() < OU_key_bytes_V5) ||
-            (OE.length() < OUE_key_bytes_V5) ||
-            (UE.length() < OUE_key_bytes_V5) ||
-            (Perms.length() < Perms_key_bytes_V5))
-        {
-            throw QPDFExc(qpdf_e_damaged_pdf, this->m->file->getName(),
-                          "encryption dictionary",
-                          this->m->file->getLastOffset(),
-                          "incorrect length for some of"
-                          " /O, /U, /OE, /UE, or /Perms in"
-                          " encryption dictionary");
-        }
     }
 
     int Length = 40;
```
