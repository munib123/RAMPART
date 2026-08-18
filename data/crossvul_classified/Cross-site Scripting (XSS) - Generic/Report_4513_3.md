# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 4513_3
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4513_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 168-188 of the vulnerable file.

throw new Error("Broken JSON "+(str[pos]==="{"?"object":"array")+" body near "+body);}
throw new Error("Broken JSON body near "+str.substr((pos-5>=0)?pos-5:0,50));}
function canBeKeyHead(ch){if(ch[0]==="\\")return false;if((ch[0]>='a'&&ch[0]<='z')||(ch[0]>='A'&&ch[0]<='Z')||ch[0]==='_')return true;if(ch[0]>='0'&&ch[0]<='9')return true;if(ch[0]==='$')return true;if(ch.charCodeAt(0)>255)return true;return false;}
function isBlankChar(ch){return ch===" "||ch==="\n"||ch==="\t";}
function parse(str){str=str.trim();if(!str.length)throw new Error("Broken JSON object.");var result="";while(str&&str[0]===","){str=str.substr(1);}
if(str[0]==="\""||str[0]==="'"){if(str[str.length-1]!==str[0]){throw new Error("Invalid string JSON object.");}
var body="\"";for(var i=1;i<str.length;i++){if(str[i]==="\\"){if(str[i+1]==="'"){body+=str[i+1]}else{body+=str[i];body+=str[i+1];}
i++;}else if(str[i]===str[0]){body+="\"";return body}else if(str[i]==="\""){body+="\\\""}else body+=str[i];}
throw new Error("Invalid string JSON object.");}
if(str==="true"||str==="false"){return str;}
if(str==="null"){return"null";}
var num=parseFloat(str);if(!isNaN(num)){return num.toString();}
if(str[0]==="{"){var type="needKey";var result="{";for(var i=1;i<str.length;i++){if(isBlankChar(str[i])){continue;}else if(type==="needKey"&&(str[i]==="\""||str[i]==="'")){var key=parseKey(str,i+1,str[i]);result+="\""+key+"\"";i+=key.length;i+=1;type="afterKey";}else if(type==="needKey"&&canBeKeyHead(str[i])){var key=parseKey(str,i);result+="\"";result+=key;result+="\"";i+=key.length-1;type="afterKey";}else if(type==="afterKey"&&str[i]===":"){result+=":";type=":";}else if(type===":"){var body=getBody(str,i);i=i+body.originLength-1;result+=parse(body.body);type="afterBody";}else if(type==="afterBody"||type==="needKey"){var last=i;while(str[last]===","||isBlankChar(str[last])){last++;}
if(str[last]==="}"&&last===str.length-1){while(result[result.length-1]===","){result=result.substr(0,result.length-1);}
result+="}";return result;}else if(last!==i&&result!=="{"){result+=",";type="needKey";i=last-1;}}}
throw new Error("Broken JSON object near "+result);}
if(str[0]==="["){var result="[";var type="needBody";for(var i=1;i<str.length;i++){if(" "===str[i]||"\n"===str[i]||"\t"===str[i]){continue;}else if(type==="needBody"){if(str[i]===","){result+="null,";continue;}
if(str[i]==="]"&&i===str.length-1){if(result[result.length-1]===",")result=result.substr(0,result.length-1);result+="]";return result;}
var body=getBody(str,i);i=i+body.originLength-1;result+=parse(body.body);type="afterBody";}else if(type==="afterBody"){if(str[i]===","){result+=",";type="needBody";while(str[i+1]===","||isBlankChar(str[i+1])){if(str[i+1]===",")result+="null,";i++;}}else if(str[i]==="]"&&i===str.length-1){result+="]";return result;}}}
throw new Error("Broken JSON array near "+result);}}
window.ocJSON=function(json){var jsonString=parse(json);return JSON.parse(jsonString);};}(window);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -185,4 +185,6 @@
 if(str[i]==="]"&&i===str.length-1){if(result[result.length-1]===",")result=result.substr(0,result.length-1);result+="]";return result;}
 var body=getBody(str,i);i=i+body.originLength-1;result+=parse(body.body);type="afterBody";}else if(type==="afterBody"){if(str[i]===","){result+=",";type="needBody";while(str[i+1]===","||isBlankChar(str[i+1])){if(str[i+1]===",")result+="null,";i++;}}else if(str[i]==="]"&&i===str.length-1){result+="]";return result;}}}
 throw new Error("Broken JSON array near "+result);}}
-window.ocJSON=function(json){var jsonString=parse(json);return JSON.parse(jsonString);};}(window);
+window.ocJSON=function(json){var jsonString=parse(json);return JSON.parse(jsonString);};}(window);+function(window){"use strict";function trimAttributes(node){$.each(node.attributes,function(){var attrName=this.name;var attrValue=this.value;if(attrName.indexOf('on')==0||attrValue.indexOf('javascript:')==0){$(node).removeAttr(attrName);}});}
+function sanitize(html){var output=$($.parseHTML('<div>'+html+'</div>',null,false));output.find('*').each(function(){trimAttributes(this);});return output.html();}
+window.ocSanitize=function(html){return sanitize(html)};}(window);
```
