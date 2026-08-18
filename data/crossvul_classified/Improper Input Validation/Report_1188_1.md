# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 1188_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1188_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 968-1010 of the vulnerable file.


      var context = {
        column: isColumns === true ? this.options.columns[this.state.record.length].name : this.state.record.length,
        empty_lines: this.info.empty_lines,
        header: this.options.columns === true,
        index: this.state.record.length,
        invalid_field_length: this.info.invalid_field_length,
        quoting: this.state.wasQuoting,
        lines: this.info.lines,
        records: this.info.records
      };

      if (this.state.castField !== null) {
        try {
          return [undefined, this.state.castField.call(null, field, context)];
        } catch (err) {
          return [err];
        }
      }

      if (this.__isInt(field) === true) {
        return [undefined, parseInt(field)];
      } else if (this.__isFloat(field)) {
        return [undefined, parseFloat(field)];
      } else if (this.options.cast_date !== false) {
        return [undefined, this.options.cast_date.call(null, field, context)];
      }

      return [undefined, field];
    }
  }, {
    key: "__isInt",
    value: function __isInt(value) {
      return /^(\-|\+)?([1-9]+[0-9]*)$/.test(value);
    }
  }, {
    key: "__isFloat",
    value: function __isFloat(value) {
      return value - parseFloat(value) + 1 >= 0; // Borrowed from jquery
    }
  }, {
    key: "__compareBytes",
    value: function __compareBytes(sourceBuf, targetBuf, pos, firtByte) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -985,21 +985,20 @@
         }
       }
 
-      if (this.__isInt(field) === true) {
-        return [undefined, parseInt(field)];
-      } else if (this.__isFloat(field)) {
+      if (this.__isFloat(field)) {
         return [undefined, parseFloat(field)];
       } else if (this.options.cast_date !== false) {
         return [undefined, this.options.cast_date.call(null, field, context)];
       }
 
       return [undefined, field];
-    }
-  }, {
-    key: "__isInt",
-    value: function __isInt(value) {
-      return /^(\-|\+)?([1-9]+[0-9]*)$/.test(value);
-    }
+    } // Keep it in case we implement the `cast_int` option
+    // __isInt(value){
+    //   // return Number.isInteger(parseInt(value))
+    //   // return !isNaN( parseInt( obj ) );
+    //   return /^(\-|\+)?[1-9][0-9]*$/.test(value)
+    // }
+
   }, {
     key: "__isFloat",
     value: function __isFloat(value) {
```
