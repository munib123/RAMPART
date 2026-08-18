# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in html
**Pair ID:** 4361_1
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** html
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4361_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

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
                    <th scope="row">4.30.4</th>
                    <td>2020-11-25</td>
                    <td>reverted Object.freeze because it broke some projects</td>
                  </tr>
                  <tr>
                    <th scope="row">4.30.3</th>
                    <td>2020-11-25</td>
                    <td>security update (prototype pollution prevention) Object.freeze</td>
                  </tr>
                  <tr>
                    <th scope="row">4.30.2</th>
                    <td>2020-11-25</td>
                    <td>security update (prototype pollution prevention)</td>
                  </tr>
                  <tr>
                    <th scope="row">4.30.1</th>
                    <td>2020-11-12</td>
                    <td>updated docs</td>
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
+                    <th scope="row">4.30.5</th>
+                    <td>2020-11-26</td>
+                    <td>adapted security update (prototype pollution prevention)</td>
+                  </tr>
+                  <tr>
                     <th scope="row">4.30.4</th>
                     <td>2020-11-25</td>
                     <td>reverted Object.freeze because it broke some projects</td>
```
