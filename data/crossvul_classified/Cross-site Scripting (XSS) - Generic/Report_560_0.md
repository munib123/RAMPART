# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 560_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `560_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 123-163 of the vulnerable file.

															stats.isDirectory = stats.isDirectory();
															stats.isBlockDevice = stats.isBlockDevice();
															stats.isFIFO = stats.isFIFO();
															stats.isSocket = stats.isSocket();
															results.push(stats);
															search.stats(files);															
														}
													});
												} else {
													if(query.type == 'json' || query.dir == 'json') {
														res.setHeader('Content-Type', 'application/json');
														res.write(JSON.stringify(results)); 
														res.end();
													} else { 
														res.setHeader('Content-Type', 'text/html');											
														res.write('<html><body>');
														for(var f = 0; f < results.length; f++) {
															var name = results[f].name;
															var normalized = url + '/' + name;
															while(normalized[0] == '/') { normalized = normalized.slice(1, normalized.length); }
															res.write('\r\n<p><a href="/' + normalized + '">' + name + '</a></p>');
														}
														res.end('\r\n</body></html>');
													}
												}
											};
											search.stats(files);
										}
									});
								} else {
									// if it's a file, return the contents of a file with the correct content type
									console.log('reading file ' + relativePath);
									if(query.type == 'json' || query.dir == 'json') {
										var type = 'application/json';
										res.setHeader('Content-Type', type);
										fs.readFile(relativePath, function(err, data) { 
											if(err) { writeError(err); }
											else {
												res.end(JSON.stringify({ 
													data: data.toString(),
													type: require('mime').lookup(relativePath),
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -140,7 +140,9 @@
 															var name = results[f].name;
 															var normalized = url + '/' + name;
 															while(normalized[0] == '/') { normalized = normalized.slice(1, normalized.length); }
-															res.write('\r\n<p><a href="/' + normalized + '">' + name + '</a></p>');
+															if(normalized.indexOf('"') >= 0) throw new Error('unsupported file name')
+															name = name.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
+															res.write('\r\n<p><a href="/' + normalized + '"><span>' + name + '</span></a></p>');
 														}
 														res.end('\r\n</body></html>');
 													}
```
