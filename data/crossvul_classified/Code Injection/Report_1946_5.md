# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 1946_5
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1946_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 14-54 of the vulnerable file.

            'green'     : [32, 39],
            'red'       : [31, 39],
            'grey'      : [90, 39]
        };
        return '\033[' + styles[style][0] + 'm' + str +
               '\033[' + styles[style][1] + 'm';
    },

    //Print command line options
    printUsage: function() {
        console.log("usage: lessc [option option=parameter ...] <source> [destination]");
        console.log("");
        console.log("If source is set to `-' (dash or hyphen-minus), input is read from stdin.");
        console.log("");
        console.log("options:");
        console.log("  -h, --help               Print help (this message) and exit.");
        console.log("  --include-path=PATHS     Set include paths. Separated by `:'. Use `;' on Windows.");
        console.log("  -M, --depends            Output a makefile import dependency list to stdout");
        console.log("  --no-color               Disable colorized output.");
        console.log("  --no-ie-compat           Disable IE compatibility checks.");
        console.log("  --no-js                  Disable JavaScript in less files");
        console.log("  -l, --lint               Syntax check only (lint).");
        console.log("  -s, --silent             Suppress output of error messages.");
        console.log("  --strict-imports         Force evaluation of imports.");
        console.log("  --insecure               Allow imports from insecure https hosts.");
        console.log("  -v, --version            Print version number and exit.");
        console.log("  -x, --compress           Compress output by removing some whitespaces.");
        console.log("  --clean-css              Compress output using clean-css");
        console.log("  --clean-option=opt:val   Pass an option to clean css, using CLI arguments from ");
        console.log("                           https://github.com/GoalSmashers/clean-css e.g.");
        console.log("                           --clean-option=--selectors-merge-mode:ie8");
        console.log("                           and to switch on advanced use --clean-option=--advanced");
        console.log("  --source-map[=FILENAME]  Outputs a v3 sourcemap to the filename (or output filename.map)");
        console.log("  --source-map-rootpath=X  adds this path onto the sourcemap filename and less file paths");
        console.log("  --source-map-basepath=X  Sets sourcemap base path, defaults to current working directory.");
        console.log("  --source-map-less-inline puts the less files into the map instead of referencing them");
        console.log("  --source-map-map-inline  puts the map (and any less files) into the output css file");
        console.log("  --source-map-url=URL     the complete url and filename put in the less file");
        console.log("  -rp, --rootpath=URL      Set rootpath for url rewriting in relative imports and urls.");
        console.log("                           Works with or without the relative-urls option.");
        console.log("  -ru, --relative-urls     re-write relative urls to the base less file.");
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -31,7 +31,9 @@
         console.log("  -M, --depends            Output a makefile import dependency list to stdout");
         console.log("  --no-color               Disable colorized output.");
         console.log("  --no-ie-compat           Disable IE compatibility checks.");
-        console.log("  --no-js                  Disable JavaScript in less files");
+        /* BEGIN MODIFICATION */
+        // Removed --no-js option
+        /* END MODIFICATION */
         console.log("  -l, --lint               Syntax check only (lint).");
         console.log("  -s, --silent             Suppress output of error messages.");
         console.log("  --strict-imports         Force evaluation of imports.");
```
