# CrossVul Fix Pair: Uncontrolled Resource Consumption in javascript
**Pair ID:** 4450_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4450_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```javascript
Lines 3-43 of the vulnerable file.

// match1 - section, match2 - optional full inheritance  part, match3 - inherited section
const REGEXP_SECTION = /^\s*\[\s*([^:]*?)\s*(:\s*(.+?)\s*)?\]\s*$/;
const REGEXP_COMMENT = /^;.*/;
const REGEXP_SINGLE_LINE = /^\s*(.*?)\s*?=\s*?(\S.*?)$/;
const REGEXP_MULTI_LINE = /^\s*(.*?)\s*?=\s*?"(.*?)$/;
const REGEXP_NOT_ESCAPED_MULTI_LINE_END = /^(.*?)\\"$/;
const REGEXP_MULTI_LINE_END = /^(.*?)"$/;
const REGEXP_ARRAY = /^(.*?)\[\]$/;

const STATUS_OK = 0;
const STATUS_INVALID = 1;

const defaults = {
    ignore_invalid: true,
    keep_quotes: false,
    oninvalid: () => true,
    filters: [],
    constants: {},
};

const REGEXP_IGNORE_KEYS = /__proto__/;

class Parser {
    constructor(options = {}) {
        this.options = Object.assign({}, defaults, options);

        this.handlers = [
            this.handleMultiLineStart,
            this.handleMultiLineEnd,
            this.handleMultiLineAppend,
            this.handleComment,
            this.handleSection,
            this.handleSingleLine,
        ];
    }

    parse(lines) {
        const ctx = {
            ini: {},
            current: {},
            multiLineKeys: false,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -20,7 +20,7 @@
     constants: {},
 };
 
-const REGEXP_IGNORE_KEYS = /__proto__/;
+const REGEXP_IGNORE_KEYS = /__proto__|constructor|prototype/;
 
 class Parser {
     constructor(options = {}) {
```
