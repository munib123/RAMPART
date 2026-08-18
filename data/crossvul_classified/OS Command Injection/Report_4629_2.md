# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in typescript
**Pair ID:** 4629_2
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** typescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4629_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```typescript
Lines 1-23 of the vulnerable file.

import * as path from 'path';
import * as log from '../utils/log';
import { execSync } from 'child_process';

// CSS Tools
import * as autoprefixer from 'autoprefixer';
import * as browserslist from 'browserslist';
import * as nodeSassTildeImporter from 'node-sass-tilde-importer';
import * as postcss from 'postcss';
import * as postcssUrl from 'postcss-url';
import * as cssnanoPresetDefault from 'cssnano-preset-default';
import * as stylus from 'stylus';

export enum CssUrl {
  inline = 'inline',
  none = 'none',
}

/*
 * Please be aware of the few differences in behaviour https://github.com/sass/dart-sass/blob/master/README.md#behavioral-differences-from-ruby-sass
 * By default `npm install` will install sass.
 * To use node-sass you need to use:
 *   Npm:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 import * as path from 'path';
 import * as log from '../utils/log';
-import { execSync } from 'child_process';
+import { execFileSync } from 'child_process';
 
 // CSS Tools
 import * as autoprefixer from 'autoprefixer';
@@ -50,7 +50,7 @@
     });
 
     // Log warnings from postcss
-    result.warnings().forEach((msg) => log.warn(msg.toString()));
+    result.warnings().forEach(msg => log.warn(msg.toString()));
 
     return result.css;
   }
@@ -75,12 +75,12 @@
 
       case '.less':
         // this is the only way I found to make LESS sync
-        let cmd = `node "${require.resolve('less/bin/lessc')}" "${filePath}" --js`;
+        const args = [filePath, '--js'];
         if (this.styleIncludePaths.length) {
-          cmd += ` --include-path="${this.styleIncludePaths.join(':')}"`;
+          args.push(`--include-path=${this.styleIncludePaths.join(':')}`);
         }
 
-        return execSync(cmd).toString();
+        return execFileSync(require.resolve('less/bin/lessc'), args).toString();
 
       case '.styl':
       case '.stylus':
@@ -126,7 +126,7 @@
     const cssNanoPlugins = preset.plugins
       // replicate the `initializePlugin` behavior from https://github.com/cssnano/cssnano/blob/a566cc5/packages/cssnano/src/index.js#L8
       .map(([creator, pluginConfig]) => creator(pluginConfig))
-      .filter((plugin) => !asyncPlugins.includes(plugin.postcssPlugin));
+      .filter(plugin => !asyncPlugins.includes(plugin.postcssPlugin));
 
     postCssPlugins.push(...cssNanoPlugins);
 
```
