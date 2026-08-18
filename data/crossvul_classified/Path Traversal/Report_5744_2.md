# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in ruby
**Pair ID:** 5744_2
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5744_2`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```ruby
Lines 1-21 of the vulnerable file.

module Wicked
  FINISH_STEP = "wicked_finish"
  FIRST_STEP  = "wicked_first"
  LAST_STEP   = "wicked_last"

  module Controller
    module Concerns
    end
  end
  module Wizard
  end
end

class WickedError < StandardError; end
class WickedProtectedStepError < WickedError; end

require 'wicked/controller/concerns/render_redirect'
require 'wicked/controller/concerns/steps'
require 'wicked/controller/concerns/path'
require 'wicked/wizard'
require 'wicked/wizard/translated'
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,3 +1,5 @@
+require 'erb'
+
 module Wicked
   FINISH_STEP = "wicked_finish"
   FIRST_STEP  = "wicked_first"
```
