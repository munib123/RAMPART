# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 5782_9
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5782_9`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 13-42 of the vulnerable file.

#    limitations under the License.

# The cached result of a `git-blame` operation. The {Blamer} uses this table as
# a write-through cache of these results by means of {Blamer::Cache}.
#
# Properties
# ----------
#
# |                   |                                                                                       |
# |:------------------|:--------------------------------------------------------------------------------------|
# | `repository_hash` | The SHA1 hash of the URL of the Git repository where the operation was run.           |
# | `revision`        | The Git revision active at the time of the blame operation.                           |
# | `file`            | The file on which the blame was run.                                                  |
# | `line`            | The line in the file on which the blame was run.                                      |
# | `blamed_revision` | The revision that most recently modified that file and line, on or before `revision`. |

class Blame < ActiveRecord::Base
  validates :repository_hash, :revision, :blamed_revision,
            presence: true,
            length:   {is: 40},
            format:   {with: /[0-9a-f]+/}
  validates :file,
            presence: true,
            length:   {maximum: 255}
  validates :line,
            presence:     true,
            numericality: {only_integer: true, greater_than: 0}

  scope :for_project, ->(project) { where(repository_hash: project.repository_hash) }
end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,7 +30,7 @@
   validates :repository_hash, :revision, :blamed_revision,
             presence: true,
             length:   {is: 40},
-            format:   {with: /[0-9a-f]+/}
+            format:   {with: /\A[0-9a-f]+\z/}
   validates :file,
             presence: true,
             length:   {maximum: 255}
```
