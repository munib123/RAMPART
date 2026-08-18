# CrossVul Fix Pair: Uncontrolled Resource Consumption in javascript
**Pair ID:** 4394_0
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4394_0`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```javascript
Lines 119-159 of the vulnerable file.


                    for (var key in props || {}) {
                        value = props[key];
                        newLocale[key] = value.slice ? value.slice() : value;
                    }
                    return newLocale;
                },
                loc = { res: extend(base.res, locale.res) };

            loc.formatter = extend(base.formatter, locale.formatter, loc.res);
            loc.parser = extend(base.parser, locale.parser, loc.res);
            locales[code] = loc;
        };

    /**
     * compiling a format string
     * @param {string} formatString - a format string
     * @returns {Array.<string>} a compiled object
     */
    date.compile = function (formatString) {
        var re = /\[([^\[\]]*|\[[^\[\]]*\])*\]|([A-Za-z])\2+|\.{3}|./g, keys, pattern = [formatString];

        while ((keys = re.exec(formatString))) {
            pattern[pattern.length] = keys[0];
        }
        return pattern;
    };

    /**
     * formatting a date
     * @param {Date} dateObj - a Date object
     * @param {string|Array.<string>} arg - a format string or a compiled object
     * @param {boolean} [utc] - output as UTC
     * @returns {string} a formatted string
     */
    date.format = function (dateObj, arg, utc) {
        var pattern = typeof arg === 'string' ? date.compile(arg) : arg,
            d = date.addMinutes(dateObj, utc ? dateObj.getTimezoneOffset() : 0),
            formatter = locales[lang].formatter, str = '';

        d.utc = utc || false;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -136,7 +136,7 @@
      * @returns {Array.<string>} a compiled object
      */
     date.compile = function (formatString) {
-        var re = /\[([^\[\]]*|\[[^\[\]]*\])*\]|([A-Za-z])\2+|\.{3}|./g, keys, pattern = [formatString];
+        var re = /\[([^\[\]]|\[[^\[\]]*])*]|([A-Za-z])\2+|\.{3}|./g, keys, pattern = [formatString];
 
         while ((keys = re.exec(formatString))) {
             pattern[pattern.length] = keys[0];
```
