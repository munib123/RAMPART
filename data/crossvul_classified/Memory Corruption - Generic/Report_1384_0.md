# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 1384_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1384_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 80-109 of the vulnerable file.

      buf.move();
    }

    return false;
  }
}

void LineBasedFrameDecoder::fail(Context* ctx, std::string len) {
  ctx->fireReadException(
    folly::make_exception_wrapper<std::runtime_error>(
      "frame length" + len +
      " exeeds max " + folly::to<std::string>(maxLength_)));
}

int64_t LineBasedFrameDecoder::findEndOfLine(IOBufQueue& buf) {
  Cursor c(buf.front());
  for (uint32_t i = 0; i < maxLength_ && i < buf.chainLength(); i++) {
    auto b = c.read<char>();
    if (b == '\n' && terminatorType_ != TerminatorType::CARRIAGENEWLINE) {
      return i;
    } else if (terminatorType_ != TerminatorType::NEWLINE &&
               b == '\r' && !c.isAtEnd() && c.read<char>() == '\n') {
      return i;
    }
  }

  return -1;
}

} // namespace wangle
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -97,8 +97,9 @@
     auto b = c.read<char>();
     if (b == '\n' && terminatorType_ != TerminatorType::CARRIAGENEWLINE) {
       return i;
-    } else if (terminatorType_ != TerminatorType::NEWLINE &&
-               b == '\r' && !c.isAtEnd() && c.read<char>() == '\n') {
+    } else if (
+        terminatorType_ != TerminatorType::NEWLINE && b == '\r' &&
+        !c.isAtEnd() && *c.peekBytes().data() == '\n') {
       return i;
     }
   }
```
