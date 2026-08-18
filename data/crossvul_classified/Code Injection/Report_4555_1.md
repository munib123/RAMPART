# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in javascript
**Pair ID:** 4555_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4555_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```javascript
Lines 15-55 of the vulnerable file.

					weight: 52,
					price: 100,
					code: "B12345",
					purchased: new Date(2016, 0, 1)
				},
				cherry: 97
			};
			var object2 = {
				banana: {
					price: 200,
					code: "B98765",
					purchased: new Date(2017, 0, 1)
				},
				durian: 100
			};
			util.deepCopy(object1, object2);
			assert.strictEqual(object1.banana.weight, 52);
			assert.strictEqual(object1.banana.price, 200);
			assert.strictEqual(object1.banana.code, "B98765");
			assert.equal(object1.banana.purchased.getTime(), new Date(2017, 0, 1).getTime());
		},

		'deepCopy with FormData': function(){
			if (has('native-formdata')) {
				var formData = new FormData();
				var object1 = {
					apple: 0,
					banana: {
						weight: 52,
						price: 100,
						code: "B12345",
						purchased: new Date(2016, 0, 1)
					},
					cherry: 97
				};
				var object2 = {
					banana: {
						price: 200,
						code: "B98765",
						purchased: new Date(2017, 0, 1)
					},
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -32,6 +32,12 @@
 			assert.strictEqual(object1.banana.price, 200);
 			assert.strictEqual(object1.banana.code, "B98765");
 			assert.equal(object1.banana.purchased.getTime(), new Date(2017, 0, 1).getTime());
+		},
+
+		'.deepCopy should ignore the __proto__ property': function() {
+			var payload = JSON.parse('{ "__proto__": { "protoPollution": true }}');
+			util.deepCopy({}, payload);
+			assert.isUndefined(({}).protoPollution);
 		},
 
 		'deepCopy with FormData': function(){
```
