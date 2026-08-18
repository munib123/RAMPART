# CrossVul Fix Pair: Uncontrolled Resource Consumption in typescript
**Pair ID:** 4372_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4372_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```typescript
Lines 1-27 of the vulnerable file.

import { Scanner } from './Scanner';
import { ColumnParser } from './column';
import { ParserOptions } from '../ParserOptions';
import { RowArray } from '../types';
import { MaybeToken, Token } from './Token';

export class RowParser {
    private readonly parserOptions: ParserOptions;

    private readonly columnParser: ColumnParser;

    public constructor(parserOptions: ParserOptions) {
        this.parserOptions = parserOptions;
        this.columnParser = new ColumnParser(parserOptions);
    }

    public parse(scanner: Scanner): RowArray | null {
        const { parserOptions } = this;
        const { hasMoreData } = scanner;
        const currentScanner = scanner;
        const columns: RowArray<string> = [];
        let currentToken = this.getStartToken(currentScanner, columns);
        while (currentToken) {
            if (Token.isTokenRowDelimiter(currentToken)) {
                currentScanner.advancePastToken(currentToken);
                // if ends with CR and there is more data, keep unparsed due to possible
                // coming LF in CRLF
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4,7 +4,13 @@
 import { RowArray } from '../types';
 import { MaybeToken, Token } from './Token';
 
+const EMPTY_STRING = '';
+
 export class RowParser {
+    static isEmptyRow(row: RowArray): boolean {
+        return row.join(EMPTY_STRING).replace(/\s+/g, EMPTY_STRING) === EMPTY_STRING;
+    }
+
     private readonly parserOptions: ParserOptions;
 
     private readonly columnParser: ColumnParser;
```
