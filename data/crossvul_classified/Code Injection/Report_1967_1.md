# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in javascript
**Pair ID:** 1967_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1967_1`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```javascript
Lines 6605-6646 of the vulnerable file.


exports.set = function(obj, path, value) {
	var cachekey = 'S+' + path;

	if (F.temporary.other[cachekey])
		return F.temporary.other[cachekey](obj, value);

	var arr = parsepath(path);
	var builder = [];

	for (var i = 0; i < arr.length - 1; i++) {
		var type = arr[i + 1] ? (REGISARR.test(arr[i + 1]) ? '[]' : '{}') : '{}';
		var p = 'w' + (arr[i][0] === '[' ? '' : '.') + arr[i];
		builder.push('if(typeof(' + p + ')!==\'object\'||' + p + '==null)' + p + '=' + type + ';');
	}

	var v = arr[arr.length - 1];
	var ispush = v.lastIndexOf('[]') !== -1;
	var a = builder.join(';') + ';var v=typeof(a)===\'function\'?a(U.get(b)):a;w' + (v[0] === '[' ? '' : '.') + (ispush ? v.replace(REGREPLACEARR, '.push(v)') : (v + '=v')) + ';return v';

	if ((/__proto__|constructor|prototype/).test(a))
		throw new Error('Prototype pollution');

	var fn = new Function('w', 'a', 'b', a);
	F.temporary.other[cachekey] = fn;
	fn(obj, value, path);
};

exports.get = function(obj, path) {

	var cachekey = 'G=' + path;

	if (F.temporary.other[cachekey])
		return F.temporary.other[cachekey](obj);

	var arr = parsepath(path);
	var builder = [];

	for (var i = 0, length = arr.length - 1; i < length; i++)
		builder.push('if(!w' + (!arr[i] || arr[i][0] === '[' ? '' : '.') + arr[i] + ')return');

	var v = arr[arr.length - 1];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -6622,8 +6622,8 @@
 	var ispush = v.lastIndexOf('[]') !== -1;
 	var a = builder.join(';') + ';var v=typeof(a)===\'function\'?a(U.get(b)):a;w' + (v[0] === '[' ? '' : '.') + (ispush ? v.replace(REGREPLACEARR, '.push(v)') : (v + '=v')) + ';return v';
 
-	if ((/__proto__|constructor|prototype/).test(a))
-		throw new Error('Prototype pollution');
+	if ((/__proto__|constructor|prototype|eval/).test(a))
+		throw new Error('Potential vulnerability');
 
 	var fn = new Function('w', 'a', 'b', a);
 	F.temporary.other[cachekey] = fn;
```
