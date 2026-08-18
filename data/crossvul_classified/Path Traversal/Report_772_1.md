# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in javascript
**Pair ID:** 772_1
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `772_1`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```javascript
Lines 476-519 of the vulnerable file.

        './src/materialize-css/js/tabs.js',
        './src/materialize-css/js/dropdown.js',
        './src/materialize-css/js/toasts.js',
        './src/materialize-css/js/modal.js',
        './src/materialize-css/js/select.js',
        './src/materialize-css/js/forms.js',
        './src/materialize-css/js/range.js',
        './src/materialize-css/js/collapsible.js',
        './src/materialize-css/js/chips.js',
        './src/materialize-css/js/datepicker.js',
        './src/materialize-css/js/autocomplete.js',
        './src/materialize-css/js/timepicker.js',
        './src/materialize-css/js/tooltip.js',
        './src/materialize-css/js/autocomplete.js',
        './src/colorpicker/js/materialize-colorpicker.js'
    ])
    .pipe(sourcemaps.init())
    .pipe(concat('materialize.js'))
    .pipe(babel({
        plugins: [
            'transform-es2015-arrow-functions',
            'transform-es2015-block-scoping',
            'transform-es2015-classes',
            'transform-es2015-template-literals'
        ]
    }))
    .pipe(uglify())    
    .pipe(sourcemaps.write('.'))
    .pipe(gulp.dest('./www/lib/js'));
});

gulp.task('configCSS', () => {
    return gulp.src([
        './src/lib/css/iob/selectID.less',
        './src/less/adapter.less',
        './src/less/materializeCorrect.less'
    ])
        .pipe(sourcemaps.init())
        .pipe(less({
            paths: [ ]
        }))
        .pipe(concat('adapter.css'))
        .pipe(cleanCSS({compatibility: 'ie8'}))
        .pipe(sourcemaps.write('.'))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -493,13 +493,13 @@
     .pipe(concat('materialize.js'))
     .pipe(babel({
         plugins: [
-            'transform-es2015-arrow-functions',
-            'transform-es2015-block-scoping',
-            'transform-es2015-classes',
-            'transform-es2015-template-literals'
+            '@babel/plugin-transform-arrow-functions',
+            '@babel/plugin-transform-block-scoping',
+            '@babel/plugin-transform-classes',
+            '@babel/plugin-transform-template-literals'
         ]
     }))
-    .pipe(uglify())    
+    .pipe(uglify())
     .pipe(sourcemaps.write('.'))
     .pipe(gulp.dest('./www/lib/js'));
 });
```
