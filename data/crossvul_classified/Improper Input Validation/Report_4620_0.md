# CrossVul Fix Pair: Improper Input Validation in coffeescript
**Pair ID:** 4620_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** coffeescript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4620_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```coffeescript
Lines 27-69 of the vulnerable file.

            else
                app['handle_error'](req, res, x)
        else
           app['handle_error'](req, res, x)
        app['log_request'](req, res, true)


fake_response = (req, res) ->
        # This is quite simplistic, don't expect much.
        headers = {'Connection': 'close'}
        res.writeHead = (status, user_headers = {}) ->
            r = []
            r.push('HTTP/' + req.httpVersion + ' ' + status +
                   ' ' + http.STATUS_CODES[status])
            utils.objectExtend(headers, user_headers)
            for k of headers
                r.push(k + ': ' + headers[k])
            r = r.concat(['', ''])
            try
                res.write(r.join('\r\n'))
            catch x
            try
                res.end()
            catch x
        res.setHeader = (k, v) -> headers[k] = v


exports.generateHandler = (app, dispatcher) ->
    return (req, res, head) ->
        if typeof res.writeHead is "undefined"
            fake_response(req, res)
        utils.objectExtend(req, url.parse(req.url, true))
        req.start_date = new Date()

        found = false
        allowed_methods = []
        for row in dispatcher
            [method, path, funs] = row
            if path.constructor isnt Array
                path = [path]
            # path[0] must be a regexp
            m = req.pathname.match(path[0])
            if not m
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,9 +44,6 @@
             r = r.concat(['', ''])
             try
                 res.write(r.join('\r\n'))
-            catch x
-            try
-                res.end()
             catch x
         res.setHeader = (k, v) -> headers[k] = v
 
```
