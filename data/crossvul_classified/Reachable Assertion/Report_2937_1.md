# CrossVul Fix Pair: Reachable Assertion in cpp
**Pair ID:** 2937_1
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2937_1`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```cpp
Lines 204-244 of the vulnerable file.

  resource.push_back('/');
  resource.append(o);
}

optional<ARN> ARN::parse(const string& s, bool wildcards) {
  static const char str_wild[] = "arn:([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)";
  static const regex rx_wild(str_wild,
				    sizeof(str_wild) - 1,
				    ECMAScript | optimize);
  static const char str_no_wild[]
    = "arn:([^:*]*):([^:*]*):([^:*]*):([^:*]*):([^:*]*)";
  static const regex rx_no_wild(str_no_wild,
				sizeof(str_no_wild) - 1,
				ECMAScript | optimize);

  smatch match;

  if ((s == "*") && wildcards) {
    return ARN(Partition::wildcard, Service::wildcard, "*", "*", "*");
  } else if (regex_match(s, match, wildcards ? rx_wild : rx_no_wild)) {
    ceph_assert(match.size() == 6);

    ARN a;
    {
      auto p = to_partition(match[1], wildcards);
      if (!p)
	return none;

      a.partition = *p;
    }
    {
      auto s = to_service(match[2], wildcards);
      if (!s) {
	return none;
      }
      a.service = *s;
    }

    a.region = match[3];
    a.account = match[4];
    a.resource = match[5];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -221,7 +221,9 @@
   if ((s == "*") && wildcards) {
     return ARN(Partition::wildcard, Service::wildcard, "*", "*", "*");
   } else if (regex_match(s, match, wildcards ? rx_wild : rx_no_wild)) {
-    ceph_assert(match.size() == 6);
+    if (match.size() != 6) {
+      return boost::none;
+    }
 
     ARN a;
     {
@@ -771,7 +773,9 @@
 			  ECMAScript | optimize);
     smatch match;
     if (regex_match(a->resource, match, rx)) {
-      ceph_assert(match.size() == 3);
+      if (match.size() != 3) {
+	return boost::none;
+      }
 
       if (match[1] == "user") {
 	return Principal::user(std::move(a->account),
@@ -843,7 +847,9 @@
     // Principals
 
   } else if (w->kind == TokenKind::princ_type) {
-    ceph_assert(pp->s.size() > 1);
+    if (pp->s.size() <= 1) {
+      return false;
+    }
     auto& pri = pp->s[pp->s.size() - 2].w->id == TokenID::Principal ?
       t->princ : t->noprinc;
 
```
