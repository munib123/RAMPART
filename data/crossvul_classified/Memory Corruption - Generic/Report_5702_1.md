# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in scala
**Pair ID:** 5702_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** scala
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5702_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```scala
Lines 10-50 of the vulnerable file.

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.liftweb
package json

import org.specs2.mutable.Specification
import org.specs2.ScalaCheck
import org.scalacheck.{Arbitrary, Gen}
import org.scalacheck.Prop._


/**
 * System under specification for JSON Parser.
 */
object JsonParserSpec extends Specification with JValueGen with ScalaCheck {
  "JSON Parser Specification".title

  "Any valid json can be parsed" in {
    val parsing = (json: JValue) => { parse(Printer.pretty(render(json))); true }
    check(forAll(genJValue)(parsing))
  }

  "Buffer size does not change parsing result" in {
    val bufSize = Gen.choose(2, 64)
    val parsing = (x: JValue, s1: Int, s2: Int) => { parseVal(x, s1) == parseVal(x, s2) }
    check(forAll(genObject, bufSize, bufSize)(parsing))
  }

  "Parsing is thread safe" in {
    import java.util.concurrent._

    val json = Examples.person
    val executor = Executors.newFixedThreadPool(100)
    val results = (0 to 100).map(_ =>
      executor.submit(new Callable[JValue] { def call = parse(json) })).toList.map(_.get)
    results.zip(results.tail).forall(pair => pair._1 == pair._2) mustEqual true
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -27,6 +27,15 @@
  * System under specification for JSON Parser.
  */
 object JsonParserSpec extends Specification with JValueGen with ScalaCheck {
+
+  private def parseBadThing(): String =     try {
+    parse("""{"user":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"<}""")
+    "x" * 1000
+  } catch {
+    case e: Throwable => e.getMessage
+  }
+
+
   "JSON Parser Specification".title
 
   "Any valid json can be parsed" in {
@@ -52,6 +61,15 @@
 
   "All valid string escape characters can be parsed" in {
     parse("[\"abc\\\"\\\\\\/\\b\\f\\n\\r\\t\\u00a0\"]") must_== JArray(JString("abc\"\\/\b\f\n\r\t\u00a0")::Nil)
+  }
+
+
+  "Parser does not bleed prior results" in {
+    parse("""{"a": "now is the time for all good men to come to the aid of their dog and eat dog food with other dogs and bark and woof and do dog things. now is the time for all good men to come to the aid of their dog and eat dog food with other dogs and bark and woof and do dog things. now is the time for all good men to come to the aid of their dog and eat dog food with other dogs and bark and woof and do dog things. now is the time for all good men to come to the aid of their dog and eat dog food with other dogs and bark and woof and do dog things. now is the time for all good men to come to the aid of their dog and eat dog food with other dogs and bark and woof and do dog things. now is the time for all good men to come to the aid of their dog and eat dog food with other dogs and bark and woof and do dog things. now is the time for all good men to come to the aid of their dog and eat dog food with other dogs and bark and woof and do dog things.now is the time for all good men to come to the aid of their dog and eat dog food with other dogs and bark and woof and do dog things"}""")
+
+    val msg = parseBadThing()
+
+    msg.length must be_<=(50)
   }
 
   "Unclosed string literal fails parsing" in {
```
