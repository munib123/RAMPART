# CrossVul Fix Pair: Improper Input Validation in java
**Pair ID:** 1381_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** java
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1381_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```java
Lines 149-189 of the vulnerable file.

        for (int i = 0;
             (set.size < 0) ? prot.peekSet() : (i < set.size);
             i++) {
          skip(prot, set.elemType, maxDepth - 1);
        }
        prot.readSetEnd();
        break;
      }
    case TType.LIST:
      {
        TList list = prot.readListBegin();
        for (int i = 0;
             (list.size < 0) ? prot.peekList() : (i < list.size);
             i++) {
          skip(prot, list.elemType, maxDepth - 1);
        }
        prot.readListEnd();
        break;
      }
    default:
      break;
    }
  }

  /**
   * Attempt to determine the protocol used to serialize some data.
   *
   * The guess is based on known specificities of supported protocols.
   * In some cases, no guess can be done, in that case we return the
   * fallback TProtocolFactory.
   * To be certain to correctly detect the protocol, the first encoded
   * field should have a field id < 256
   *
   * @param data The serialized data to guess the protocol for.
   * @param fallback The TProtocol to return if no guess can be made.
   * @return a Class implementing TProtocolFactory which can be used to create a deserializer.
   */
  public static TProtocolFactory guessProtocolFactory(byte[] data, TProtocolFactory fallback) {
    //
    // If the first and last bytes are opening/closing curly braces we guess the protocol as
    // being TJSONProtocol.
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -166,7 +166,10 @@
         break;
       }
     default:
-      break;
+      {
+        throw new TProtocolException(
+              TProtocolException.INVALID_DATA, "Invalid type encountered during skipping: " + type);
+      }
     }
   }
 
```
