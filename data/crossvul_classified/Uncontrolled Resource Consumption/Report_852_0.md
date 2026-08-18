# CrossVul Fix Pair: Uncontrolled Resource Consumption in cpp
**Pair ID:** 852_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `852_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```cpp
Lines 61-103 of the vulnerable file.

      break;
    }
    case FieldType::Double: {
      readRaw<double>();
      break;
    }
    case FieldType::Float: {
      readRaw<float>();
      break;
    }
    case FieldType::Binary: {
      readRaw<std::string>();
      break;
    }
    case FieldType::List: {
      skipLinearContainer();
      break;
    }
    case FieldType::Struct: {
      readStructBegin();
      while (true) {
        const auto fieldType = readFieldHeader().first;
        if (fieldType == FieldType::Stop) {
          break;
        }
        skip(fieldType);
      }
      readStructEnd();
      break;
    }
    case FieldType::Set: {
      skipLinearContainer();
      break;
    }
    case FieldType::Map: {
      skipKVContainer();
      break;
    }
    default: { break; }
  }
}

} // carbon
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -78,13 +78,11 @@
     }
     case FieldType::Struct: {
       readStructBegin();
-      while (true) {
-        const auto fieldType = readFieldHeader().first;
-        if (fieldType == FieldType::Stop) {
-          break;
-        }
-        skip(fieldType);
-      }
+      const auto next = readFieldHeader().first;
+      skip(next);
+      break;
+    }
+    case FieldType::Stop: {
       readStructEnd();
       break;
     }
@@ -96,8 +94,10 @@
       skipKVContainer();
       break;
     }
-    default: { break; }
+    default: {
+      break;
+    }
   }
 }
 
-} // carbon
+} // namespace carbon
```
