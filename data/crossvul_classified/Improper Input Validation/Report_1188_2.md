# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 1188_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1188_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 730-772 of the vulnerable file.

    }
    const context = {
      column: isColumns === true ?
        this.options.columns[this.state.record.length].name :
        this.state.record.length,
      empty_lines: this.info.empty_lines,
      header: this.options.columns === true,
      index: this.state.record.length,
      invalid_field_length: this.info.invalid_field_length,
      quoting: this.state.wasQuoting,
      lines: this.info.lines,
      records: this.info.records
    }
    if(this.state.castField !== null){
      try{
        return [undefined, this.state.castField.call(null, field, context)]
      }catch(err){
        return [err]
      }
    }
    if(this.__isInt(field) === true){
      return [undefined, parseInt(field)]
    }else if(this.__isFloat(field)){
      return [undefined, parseFloat(field)]
    }else if(this.options.cast_date !== false){
      return [undefined, this.options.cast_date.call(null, field, context)]
    }
    return [undefined, field]
  }
  __isInt(value){
    return /^(\-|\+)?([1-9]+[0-9]*)$/.test(value)
  }
  __isFloat(value){
    return (value - parseFloat( value ) + 1) >= 0 // Borrowed from jquery
  }
  __compareBytes(sourceBuf, targetBuf, pos, firtByte){
    if(sourceBuf[0] !== firtByte) return 0
    const sourceLength = sourceBuf.length
    for(let i = 1; i < sourceLength; i++){
      if(sourceBuf[i] !== targetBuf[pos+i]) return 0
    }
    return sourceLength
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -747,18 +747,19 @@
         return [err]
       }
     }
-    if(this.__isInt(field) === true){
-      return [undefined, parseInt(field)]
-    }else if(this.__isFloat(field)){
+    if(this.__isFloat(field)){
       return [undefined, parseFloat(field)]
     }else if(this.options.cast_date !== false){
       return [undefined, this.options.cast_date.call(null, field, context)]
     }
     return [undefined, field]
   }
-  __isInt(value){
-    return /^(\-|\+)?([1-9]+[0-9]*)$/.test(value)
-  }
+  // Keep it in case we implement the `cast_int` option
+  // __isInt(value){
+  //   // return Number.isInteger(parseInt(value))
+  //   // return !isNaN( parseInt( obj ) );
+  //   return /^(\-|\+)?[1-9][0-9]*$/.test(value)
+  // }
   __isFloat(value){
     return (value - parseFloat( value ) + 1) >= 0 // Borrowed from jquery
   }
```
