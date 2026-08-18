# CrossVul Fix Pair: Improper Input Validation in javascript
**Pair ID:** 1949_2
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1949_2`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```javascript
Lines 1-36 of the vulnerable file.

'use strict'

const t = require('tap')
const Fastify = require('fastify')
const From = require('..')
const fs = require('fs')
const querystring = require('querystring')
const http = require('http')
const get = require('simple-get').concat

if (process.platform === 'win32') {
  t.pass()
  process.exit(0)
}

const instance = Fastify()
instance.register(From)

t.plan(10)
t.tearDown(instance.close.bind(instance))

const socketPath = `${__filename}.socket`

try {
  fs.unlinkSync(socketPath)
} catch (_) {
}

const target = http.createServer((req, res) => {
  t.pass('request proxied')
  t.equal(req.method, 'GET')
  t.equal(req.url, '/hello')
  res.statusCode = 205
  res.setHeader('Content-Type', 'text/plain')
  res.setHeader('x-my-header', 'hello!')
  res.end('hello world')
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -13,13 +13,14 @@
   process.exit(0)
 }
 
+const socketPath = `${__filename}.socket`
+const upstream = `unix+http://${querystring.escape(socketPath)}/`
+
 const instance = Fastify()
-instance.register(From)
+instance.register(From, { base: upstream })
 
 t.plan(10)
 t.tearDown(instance.close.bind(instance))
-
-const socketPath = `${__filename}.socket`
 
 try {
   fs.unlinkSync(socketPath)
@@ -37,7 +38,7 @@
 })
 
 instance.get('/', (request, reply) => {
-  reply.from(`unix+http://${querystring.escape(socketPath)}/hello`)
+  reply.from('hello')
 })
 
 t.tearDown(target.close.bind(target))
```
