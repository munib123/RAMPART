# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 2937_0
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2937_0`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 143-183 of the vulnerable file.

    return Principal(Tenant, std::move(t), {});
  }

  bool is_wildcard() const {
    return t == Wildcard;
  }

  bool is_user() const {
    return t == User;
  }

  bool is_role() const {
    return t == Role;
  }

  bool is_tenant() const {
    return t == Tenant;
  }

  const std::string& get_tenant() const {
    ceph_assert(t != Wildcard);
    return u.tenant;
  }

  const std::string& get_id() const {
    ceph_assert(t != Wildcard && t != Tenant);
    return u.id;
  }

  bool operator ==(const Principal& o) const {
    return (t == o.t) && (u == o.u);
  }

  bool operator <(const Principal& o) const {
    return (t < o.t) || ((t == o.t) && (u < o.u));
  }
};

std::ostream& operator <<(std::ostream& m, const Principal& p);
std::string to_string(const Principal& p);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -160,12 +160,10 @@
   }
 
   const std::string& get_tenant() const {
-    ceph_assert(t != Wildcard);
     return u.tenant;
   }
 
   const std::string& get_id() const {
-    ceph_assert(t != Wildcard && t != Tenant);
     return u.id;
   }
 
```
