# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in cpp
**Pair ID:** 20_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `20_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```cpp
Lines 1373-1413 of the vulnerable file.

bool IsBlacklistedArg(const base::CommandLine::CharType* arg) {
#if defined(OS_WIN)
  const auto converted = base::WideToUTF8(arg);
  const char* a = converted.c_str();
#else
  const char* a = arg;
#endif

  static const char* prefixes[] = {"--", "-", "/"};

  int prefix_length = 0;
  for (auto& prefix : prefixes) {
    if (base::StartsWith(a, prefix, base::CompareCase::SENSITIVE)) {
      prefix_length = strlen(prefix);
      break;
    }
  }

  if (prefix_length > 0) {
    a += prefix_length;
    std::string switch_name(a, strcspn(a, "="));
    auto* iter = std::lower_bound(std::begin(kBlacklist), std::end(kBlacklist),
                                  switch_name);
    if (iter != std::end(kBlacklist) && switch_name == *iter) {
      return true;
    }
  }

  return false;
}

}  // namespace

namespace atom {

bool CheckCommandLineArguments(int argc, base::CommandLine::CharType** argv) {
  DCHECK(std::is_sorted(std::begin(kBlacklist), std::end(kBlacklist),
                        [](const char* a, const char* b) {
                          return base::StringPiece(a) < base::StringPiece(b);
                        }))
      << "The kBlacklist must be in sorted order";
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1390,7 +1390,8 @@
 
   if (prefix_length > 0) {
     a += prefix_length;
-    std::string switch_name(a, strcspn(a, "="));
+    std::string switch_name =
+        base::ToLowerASCII(base::StringPiece(a, strcspn(a, "=")));
     auto* iter = std::lower_bound(std::begin(kBlacklist), std::end(kBlacklist),
                                   switch_name);
     if (iter != std::end(kBlacklist) && switch_name == *iter) {
```
