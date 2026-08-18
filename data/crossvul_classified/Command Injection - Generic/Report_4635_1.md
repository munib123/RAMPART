# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in html
**Pair ID:** 4635_1
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4635_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```html
Lines 66-106 of the vulnerable file.

                <li>added TypeScript definitions </li>
              </ul>
              <p><strong>Be aware</strong>, that the new version 4.x is <strong>NOT fully backward compatible</strong> to version 3.x ...</p>

              <h3>Major (breaking) Changes - Version 3</h3>
              <ul>
                <li>works only with <span class="code">node.js</span> v4.0.0 and above (using now internal ES6 promise function, arrow functions, ...)</li>
                <li><strong>Promises</strong>. As you can see in the documentation, you can now also use it in a promise oriented way. But callbacks are still supported.</li>
                <li><strong>Async/Await</strong>. Due to the promises support, systeminformation also works perfectly with the `async/await` pattern (available in <span class="code">node.js</span> <strong>v7.6.0</strong> and above). See example in the docs.</li>
              </ul>
              <h3>Full version history</h3>
              <table class="table table-sm table-bordered table-striped">
                <thead>
                  <tr>
                    <th scope="col">Version</th>
                    <th scope="col">Date</th>
                    <th scope="col">Comment</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <th scope="row">4.27.10</th>
                    <td>2020-10-16</td>
                    <td><span class="code">dockerContainers()</span> resolved hanging issue</td>
                  </tr>
                  <tr>
                    <th scope="row">4.27.9</th>
                    <td>2020-10-13</td>
                    <td><span class="code">networkInterfaces()</span> loopback internal detection (windows)</td>
                  </tr>
                  <tr>
                    <th scope="row">4.27.8</th>
                    <td>2020-10-08</td>
                    <td>windows codepages partial fix</td>
                  </tr>
                  <tr>
                    <th scope="row">4.27.7</th>
                    <td>2020-10-05</td>
                    <td>updated typescript typings, minor fixes</td>
                  </tr>
                  <tr>
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -84,6 +84,11 @@
                 </thead>
                 <tbody>
                   <tr>
+                    <th scope="row">4.27.11</th>
+                    <td>2020-10-26</td>
+                    <td><span class="code">inetChecksite()</span> fixed vulnerability: command injection</td>
+                  </tr>
+                  <tr>
                     <th scope="row">4.27.10</th>
                     <td>2020-10-16</td>
                     <td><span class="code">dockerContainers()</span> resolved hanging issue</td>
```
