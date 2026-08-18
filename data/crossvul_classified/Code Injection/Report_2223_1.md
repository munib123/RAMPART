# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in python
**Pair ID:** 2223_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2223_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```python
Lines 1048-1093 of the vulnerable file.

            ast.Load,
            ast.BinOp,
            ast.UnaryOp,
            ast.Num,
            ast.Name,
            ast.Add,
            ast.Sub,
            ast.Mult,
            ast.Div,
        )
    )

    # AST node types were expanded after 2.6
    if not sys.version.startswith('2.6'):
        SAFE_NODES.union(
            set(
                (ast.Set,)
            )
        )

    # builtin functions that are not safe to call
    INVALID_CALLS = (
       'classmethod', 'compile', 'delattr', 'eval', 'execfile', 'file',
       'filter', 'help', 'input', 'object', 'open', 'raw_input', 'reduce',
       'reload', 'repr', 'setattr', 'staticmethod', 'super', 'type',
    )

    class CleansingNodeVisitor(ast.NodeVisitor):
        def generic_visit(self, node):
            if type(node) not in SAFE_NODES:
                #raise Exception("invalid expression (%s) type=%s" % (expr, type(node)))
                raise Exception("invalid expression (%s)" % expr)
            super(CleansingNodeVisitor, self).generic_visit(node)
        def visit_Call(self, call):
            if call.func.id in INVALID_CALLS:
                raise Exception("invalid function: %s" % call.func.id)

    if not isinstance(expr, basestring):
        # already templated to a datastructure, perhaps?
        if include_exceptions:
            return (expr, None)
        return expr

    try:
        parsed_tree = ast.parse(expr, mode='eval')
        cnv = CleansingNodeVisitor()
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1065,21 +1065,31 @@
             )
         )
 
-    # builtin functions that are not safe to call
-    INVALID_CALLS = (
-       'classmethod', 'compile', 'delattr', 'eval', 'execfile', 'file',
-       'filter', 'help', 'input', 'object', 'open', 'raw_input', 'reduce',
-       'reload', 'repr', 'setattr', 'staticmethod', 'super', 'type',
-    )
+    # builtin functions that are safe to call
+    BUILTIN_WHITELIST = [
+        'abs', 'all', 'any', 'basestring', 'bin', 'bool', 'buffer', 'bytearray',
+        'bytes', 'callable', 'chr', 'cmp', 'coerce', 'complex', 'copyright', 'credits',
+        'dict', 'dir', 'divmod', 'enumerate', 'exit', 'float', 'format', 'frozenset',
+        'getattr', 'globals', 'hasattr', 'hash', 'hex', 'id', 'int', 'intern',
+        'isinstance', 'issubclass', 'iter', 'len', 'license', 'list', 'locals', 'long',
+        'map', 'max', 'memoryview', 'min', 'next', 'oct', 'ord', 'pow', 'print',
+        'property', 'quit', 'range', 'reversed', 'round', 'set', 'slice', 'sorted',
+        'str', 'sum', 'tuple', 'unichr', 'unicode', 'vars', 'xrange', 'zip',
+    ]
+
+    filter_list = []
+    for filter in filter_loader.all():
+        filter_list.extend(filter.filters().keys())
+
+    CALL_WHITELIST = BUILTIN_WHITELIST + filter_list + C.DEFAULT_CALLABLE_WHITELIST
 
     class CleansingNodeVisitor(ast.NodeVisitor):
         def generic_visit(self, node):
             if type(node) not in SAFE_NODES:
-                #raise Exception("invalid expression (%s) type=%s" % (expr, type(node)))
                 raise Exception("invalid expression (%s)" % expr)
             super(CleansingNodeVisitor, self).generic_visit(node)
         def visit_Call(self, call):
-            if call.func.id in INVALID_CALLS:
+            if call.func.id not in CALL_WHITELIST:
                 raise Exception("invalid function: %s" % call.func.id)
 
     if not isinstance(expr, basestring):
```
