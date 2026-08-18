# CrossVul Fix Pair: Use of Externally-Controlled Format String in python
**Pair ID:** 4885_0
**Vulnerability Class:** Use of Externally-Controlled Format String
**CWE:** CWE-134
**Language:** python
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4885_0`)

## Vulnerability Information & PoC

## Description
Use of Externally-Controlled Format String - When an attacker can modify an externally-controlled format string, this can lead to buffer overflows, denial of service, or data representation problems.

## Vulnerable Code
```python
Lines 587-627 of the vulnerable file.



class Test(Expr):
    """Applies a test on an expression.  `name` is the name of the test, the
    rest of the fields are the same as for :class:`Call`.
    """
    fields = ('node', 'name', 'args', 'kwargs', 'dyn_args', 'dyn_kwargs')


class Call(Expr):
    """Calls an expression.  `args` is a list of arguments, `kwargs` a list
    of keyword arguments (list of :class:`Keyword` nodes), and `dyn_args`
    and `dyn_kwargs` has to be either `None` or a node that is used as
    node for dynamic positional (``*args``) or keyword (``**kwargs``)
    arguments.
    """
    fields = ('node', 'args', 'kwargs', 'dyn_args', 'dyn_kwargs')

    def as_const(self, eval_ctx=None):
        eval_ctx = get_eval_context(self, eval_ctx)
        if eval_ctx.volatile:
            raise Impossible()
        obj = self.node.as_const(eval_ctx)

        # don't evaluate context functions
        args = [x.as_const(eval_ctx) for x in self.args]
        if isinstance(obj, _context_function_types):
            if getattr(obj, 'contextfunction', False):
                raise Impossible()
            elif getattr(obj, 'evalcontextfunction', False):
                args.insert(0, eval_ctx)
            elif getattr(obj, 'environmentfunction', False):
                args.insert(0, self.environment)

        kwargs = dict(x.as_const(eval_ctx) for x in self.kwargs)
        if self.dyn_args is not None:
            try:
                args.extend(self.dyn_args.as_const(eval_ctx))
            except Exception:
                raise Impossible()
        if self.dyn_kwargs is not None:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -604,7 +604,7 @@
 
     def as_const(self, eval_ctx=None):
         eval_ctx = get_eval_context(self, eval_ctx)
-        if eval_ctx.volatile:
+        if eval_ctx.volatile or eval_ctx.environment.sandboxed:
             raise Impossible()
         obj = self.node.as_const(eval_ctx)
 
```
