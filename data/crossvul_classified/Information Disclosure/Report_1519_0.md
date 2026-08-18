# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in javascript
**Pair ID:** 1519_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1519_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```javascript
Lines 6-46 of the vulnerable file.

 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS-IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


var async = require("async");
var db = require("../db/DB").db;
var ERR = require("async-stacktrace");

exports.getPadRaw = function(padId, callback){
  async.waterfall([
  function(cb){

    // Get the Pad available content keys
    db.findKeys("pad:"+padId+"*", null, function(err,records){
      if(!err){
        cb(err, records);
      }
    })
  },
  function(records, cb){
    var data = {};

    async.forEachSeries(Object.keys(records), function(key, r){

      // For each piece of info about a pad.
      db.get(records[key], function(err, entry){
        data[records[key]] = entry;

        // Get the Pad Authors
        if(entry.pool && entry.pool.numToAttrib){
          var authors = entry.pool.numToAttrib;
          async.forEachSeries(Object.keys(authors), function(k, c){
            if(authors[k][0] === "author"){
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -23,9 +23,19 @@
   async.waterfall([
   function(cb){
 
+    // Get the Pad
+    db.findKeys("pad:"+padId, null, function(err,padcontent){
+      if(!err){
+        cb(err, padcontent);
+      }
+    })
+  },
+  function(padcontent,cb){
+
     // Get the Pad available content keys
-    db.findKeys("pad:"+padId+"*", null, function(err,records){
+    db.findKeys("pad:"+padId+":*", null, function(err,records){
       if(!err){
+        for (var key in padcontent) { records.push(padcontent[key]);}
         cb(err, records);
       }
     })
```
