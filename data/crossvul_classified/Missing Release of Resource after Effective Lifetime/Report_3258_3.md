# CrossVul Fix Pair: Missing Release of Resource after Effective Lifetime in c
**Pair ID:** 3258_3
**Vulnerability Class:** Missing Release of Resource after Effective Lifetime
**CWE:** CWE-772
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3258_3`)

## Vulnerability Information & PoC

## Description
Missing Release of Resource after Effective Lifetime - When a resource is not released after use, it can allow attackers to cause a denial of service by causing the allocation of resources without triggering their release.

## Vulnerable Code
```c
Lines 179-205 of the vulnerable file.


    void setReader(SMsgReader *r) { reader_ = r; }
    void setWriter(SMsgWriter *w) { writer_ = w; }

  private:
    void writeFakeColourMap(void);

    bool readyForSetColourMapEntries;

    void processVersionMsg();
    void processSecurityTypeMsg();
    void processSecurityType(int secType);
    void processSecurityMsg();
    void processInitMsg();

    int defaultMajorVersion, defaultMinorVersion;
    rdr::InStream* is;
    rdr::OutStream* os;
    SMsgReader* reader_;
    SMsgWriter* writer_;
    SecurityServer *security;
    SSecurity* ssecurity;
    stateEnum state_;
    rdr::S32 preferredEncoding;
  };
}
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -196,7 +196,7 @@
     rdr::OutStream* os;
     SMsgReader* reader_;
     SMsgWriter* writer_;
-    SecurityServer *security;
+    SecurityServer security;
     SSecurity* ssecurity;
     stateEnum state_;
     rdr::S32 preferredEncoding;
```
