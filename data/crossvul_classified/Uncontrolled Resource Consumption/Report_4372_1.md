# CrossVul Fix Pair: Uncontrolled Resource Consumption in typescript
**Pair ID:** 4372_1
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4372_1`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```typescript
Lines 1-27 of the vulnerable file.

import { Scanner } from './Scanner';
import { RowParser } from './RowParser';
import { ParserOptions } from '../ParserOptions';
import { RowArray } from '../types';
import { Token } from './Token';

const EMPTY_ROW_REGEXP = /^\s*(?:''|"")?\s*(?:,\s*(?:''|"")?\s*)*$/;

export interface ParseResult {
    line: string;
    rows: string[][];
}
export class Parser {
    private static removeBOM(line: string): string {
        // Catches EFBBBF (UTF-8 BOM) because the buffer-to-string
        // conversion translates it to FEFF (UTF-16 BOM)
        if (line && line.charCodeAt(0) === 0xfeff) {
            return line.slice(1);
        }
        return line;
    }

    private readonly parserOptions: ParserOptions;

    private readonly rowParser: RowParser;

    public constructor(parserOptions: ParserOptions) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3,8 +3,6 @@
 import { ParserOptions } from '../ParserOptions';
 import { RowArray } from '../types';
 import { Token } from './Token';
-
-const EMPTY_ROW_REGEXP = /^\s*(?:''|"")?\s*(?:,\s*(?:''|"")?\s*)*$/;
 
 export interface ParseResult {
     line: string;
@@ -79,7 +77,7 @@
         if (row === null) {
             return false;
         }
-        if (this.parserOptions.ignoreEmpty && EMPTY_ROW_REGEXP.test(row.join(''))) {
+        if (this.parserOptions.ignoreEmpty && RowParser.isEmptyRow(row)) {
             return true;
         }
         rows.push(row);
```
