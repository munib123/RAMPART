# CrossVul Fix Pair: Out-of-bounds Read in cpp
**Pair ID:** 2323_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2323_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```cpp
Lines 347-387 of the vulnerable file.

        temp2 = temp2.toBase64();
    else //cut off the 8bits of IV
        temp2 = temp2.remove(0, 8);

    return temp2;
}


QByteArray Cipher::blowfishECB(QByteArray cipherText, bool direction)
{
    QCA::Initializer init;
    QByteArray temp = cipherText;

    //do padding ourselves
    if (direction)
    {
        while ((temp.length() % 8) != 0) temp.append('\0');
    }
    else
    {
        temp = b64ToByte(temp);
        while ((temp.length() % 8) != 0) temp.append('\0');
    }

    QCA::Direction dir = (direction) ? QCA::Encode : QCA::Decode;
    QCA::Cipher cipher(m_type, QCA::Cipher::ECB, QCA::Cipher::NoPadding, dir, m_key);
    QByteArray temp2 = cipher.update(QCA::MemoryRegion(temp)).toByteArray();
    temp2 += cipher.final().toByteArray();

    if (!cipher.ok())
        return cipherText;

    if (direction)
        temp2 = byteToB64(temp2);

    return temp2;
}


//Custom non RFC 2045 compliant Base64 enc/dec code for mircryption / FiSH compatibility
QByteArray Cipher::byteToB64(QByteArray text)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -364,6 +364,10 @@
     }
     else
     {
+        // ECB Blowfish encodes in blocks of 12 chars, so anything else is malformed input
+        if ((temp.length() % 12) != 0)
+            return cipherText;
+
         temp = b64ToByte(temp);
         while ((temp.length() % 8) != 0) temp.append('\0');
     }
@@ -376,8 +380,13 @@
     if (!cipher.ok())
         return cipherText;
 
-    if (direction)
+    if (direction) {
+        // Sanity check
+        if ((temp2.length() % 8) != 0)
+            return cipherText;
+
         temp2 = byteToB64(temp2);
+    }
 
     return temp2;
 }
```
