# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 1630_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1630_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 1-19 of the vulnerable file.

require "logger"
require "stringio"
require "monitor"
require "forwardable"

require "moped/bson"
require "moped/cluster"
require "moped/collection"
require "moped/cursor"
require "moped/database"
require "moped/errors"
require "moped/indexes"
require "moped/logging"
require "moped/protocol"
require "moped/query"
require "moped/server"
require "moped/session"
require "moped/socket"
require "moped/version"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6,14 +6,16 @@
 require "moped/bson"
 require "moped/cluster"
 require "moped/collection"
+require "moped/connection"
 require "moped/cursor"
 require "moped/database"
 require "moped/errors"
 require "moped/indexes"
 require "moped/logging"
+require "moped/node"
 require "moped/protocol"
 require "moped/query"
-require "moped/server"
 require "moped/session"
-require "moped/socket"
+require "moped/session/context"
+require "moped/threaded"
 require "moped/version"
```
