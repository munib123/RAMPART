# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 2937_2
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2937_2`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 11-52 of the vulnerable file.

#include <string>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>
#include <boost/optional.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <boost/utility/string_ref.hpp>
#include <boost/variant.hpp>

#include "common/ceph_time.h"
#include "common/iso_8601.h"

#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"

#include "rgw_acl.h"
#include "rgw_basic_types.h"
#include "rgw_iam_policy_keywords.h"
#include "rgw_string.h"

#include "include/assert.h" // razzin' frazzin' ...grrr.

class RGWRados;
namespace rgw {
namespace auth {
class Identity;
}
}
struct rgw_obj;
struct rgw_bucket;

namespace rgw {
namespace IAM {
static constexpr std::uint64_t s3None = 0;
static constexpr std::uint64_t s3GetObject = 1ULL << 0;
static constexpr std::uint64_t s3GetObjectVersion = 1ULL << 1;
static constexpr std::uint64_t s3PutObject = 1ULL << 2;
static constexpr std::uint64_t s3GetObjectAcl = 1ULL << 3;
static constexpr std::uint64_t s3GetObjectVersionAcl = 1ULL << 4;
static constexpr std::uint64_t s3PutObjectAcl = 1ULL << 5;
static constexpr std::uint64_t s3PutObjectVersionAcl = 1ULL << 6;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -28,8 +28,6 @@
 #include "rgw_basic_types.h"
 #include "rgw_iam_policy_keywords.h"
 #include "rgw_string.h"
-
-#include "include/assert.h" // razzin' frazzin' ...grrr.
 
 class RGWRados;
 namespace rgw {
@@ -254,7 +252,6 @@
 inline bool operator ==(const MaskedIP& l, const MaskedIP& r) {
   auto shift = std::max((l.v6 ? 128 : 32) - l.prefix,
 			(r.v6 ? 128 : 32) - r.prefix);
-  ceph_assert(shift > 0);
   return (l.addr >> shift) == (r.addr >> shift);
 }
 
```
