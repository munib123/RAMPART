# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 53_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `53_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 260-304 of the vulnerable file.

					method:"get",
					asynchronous:true,
					onSuccess:changeOwnersSelect,
					onFailure:resultError
				});

			var name = jsonData.domain.name;
			var result  = '<p><table>';
			result += '  <tr>';
			result += '	<td><h3>Edit domain :: <b>'+name+'</b> ('+jsonData.records.length+')</h3></td>';
			result += '  </tr>';
			result += '  <tr>';
			result += '	<td><form name="editDomain" action="javascript:saveAllRecords(document.editDomain);">';
			result += '	<input type="hidden" id="domainId" value="'+jsonData.domain.id+'" /><table id="recordsTable">';
			result += '	<tr><td><b>name</b></td><td><b>type</b></td><td><b>content</b></td><td><b>prio</b></td><td><b>ttl</b></td><td>&nbsp;</td><td>&nbsp;</td></tr>';
			
			for(i=0; i<jsonData.records.length; i++)
			{
				var r = jsonData.records[i];
				result += '<tr>';
				result += '<td><input type="text" value="'+r.name.replace(name, '')+'" id="name['+i+']"><input type="hidden" value="'+r.id+'" id="id['+i+']"></td>';
				result += '<td><input type="text" size="6" class="type" value="'+r.type+'" id="type['+i+']"></td>';
				result += '<td><input type="text" size="50" value="'+r.content.replace(/"/g, '&quot;')+'" id="content['+i+']"></td>';
				result += '<td><input type="text" size="2" class="num" value="'+r.prio+'" id="prio['+i+']"></td>';
				result += '<td><input type="text" size="4" class="num" value="'+r.ttl+'" id="ttl['+i+']"></td>';
				result += '<td><input type="button" onclick="removeRecord('+r.id+', '+jsonData.domain.id+');setTimeout(\'editDomain('+jsonData.domain.id+');\', '+timeoutInMilisec+');" value="delete" id="delete['+i+']"></td>';
				result += '<td><input type="button" onclick="javascript:saveRecord('+jsonData.domain.id+', document.getElementById(\'id['+i+']\').value, ';
				result += 'document.getElementById(\'name['+i+']\').value, document.getElementById(\'type['+i+']\').value, ';
				result += 'document.getElementById(\'content['+i+']\').value, document.getElementById(\'prio['+i+']\').value, ';
				result += 'document.getElementById(\'ttl['+i+']\').value); setTimeout(\'editDomain('+jsonData.domain.id+');\', '+timeoutInMilisec+');" id="save['+i+']" value="save record"></td>';
				result += '</tr>';
			}
			
			result += '	<tr><td colspan="7"><input type="submit" value="save all changes"></td></tr></table></form></td>';
			result += '  </tr>';
			result += '  <tr>';
			result += '	<td><h3>Add a record</h3></td>';
			result += '  </tr>';
			result += '  <tr>';
			result += '	   <td><table>';
			result += '	   <tr><td><b>name</b></td><td><b>type</b></td><td><b>content</b></td><td><b>prio</b></td><td><b>ttl</b></td><td>&nbsp;</td></tr>';
			result += '    <tr><td><input type="text" value="'+(lastAddedName?lastAddedName:r.name.replace(name,''))+'" id="new[name]" /></td>';
			result += '    <td><select id="new[type]"><option selected="selected" value="A">A</option>';
			result += '    <option value="AAAA">AAAA</option><option value="CNAME">CNAME</option>';
			result += '    <option value="HINFO">HINFO</option><option value="MX">MX</option>';
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -277,11 +277,11 @@
 			{
 				var r = jsonData.records[i];
 				result += '<tr>';
-				result += '<td><input type="text" value="'+r.name.replace(name, '')+'" id="name['+i+']"><input type="hidden" value="'+r.id+'" id="id['+i+']"></td>';
-				result += '<td><input type="text" size="6" class="type" value="'+r.type+'" id="type['+i+']"></td>';
-				result += '<td><input type="text" size="50" value="'+r.content.replace(/"/g, '&quot;')+'" id="content['+i+']"></td>';
-				result += '<td><input type="text" size="2" class="num" value="'+r.prio+'" id="prio['+i+']"></td>';
-				result += '<td><input type="text" size="4" class="num" value="'+r.ttl+'" id="ttl['+i+']"></td>';
+				result += '<td><input type="text" value="'+r.name.replace(name, '').escapeHTML()+'" id="name['+i+']"><input type="hidden" value="'+r.id+'" id="id['+i+']"></td>';
+				result += '<td><input type="text" size="6" class="type" value="'+r.type.escapeHTML()+'" id="type['+i+']"></td>';
+				result += '<td><input type="text" size="50" value="'+r.content.escapeHTML()+'" id="content['+i+']"></td>';
+				result += '<td><input type="text" size="2" class="num" value="'+r.prio.escapeHTML()+'" id="prio['+i+']"></td>';
+				result += '<td><input type="text" size="4" class="num" value="'+r.ttl.escapeHTML()+'" id="ttl['+i+']"></td>';
 				result += '<td><input type="button" onclick="removeRecord('+r.id+', '+jsonData.domain.id+');setTimeout(\'editDomain('+jsonData.domain.id+');\', '+timeoutInMilisec+');" value="delete" id="delete['+i+']"></td>';
 				result += '<td><input type="button" onclick="javascript:saveRecord('+jsonData.domain.id+', document.getElementById(\'id['+i+']\').value, ';
 				result += 'document.getElementById(\'name['+i+']\').value, document.getElementById(\'type['+i+']\').value, ';
@@ -298,7 +298,7 @@
 			result += '  <tr>';
 			result += '	   <td><table>';
 			result += '	   <tr><td><b>name</b></td><td><b>type</b></td><td><b>content</b></td><td><b>prio</b></td><td><b>ttl</b></td><td>&nbsp;</td></tr>';
-			result += '    <tr><td><input type="text" value="'+(lastAddedName?lastAddedName:r.name.replace(name,''))+'" id="new[name]" /></td>';
+			result += '    <tr><td><input type="text" value="'+(lastAddedName?lastAddedName:r.name.replace(name,'')).escapeHTML()+'" id="new[name]" /></td>';
 			result += '    <td><select id="new[type]"><option selected="selected" value="A">A</option>';
 			result += '    <option value="AAAA">AAAA</option><option value="CNAME">CNAME</option>';
 			result += '    <option value="HINFO">HINFO</option><option value="MX">MX</option>';
@@ -306,7 +306,7 @@
 			result += '    <option value="PTR">PTR</option><option value="SOA">SOA</option>';
 			result += '    <option value="TXT">TXT</option><option value="URL">URL</option>';
 			result += '    <option value="SRV">SRV</option><option value="MBOXFW">MBOXFW</option></select></td>';
-			result += '	   <td><input type="content" size="50" value="'+lastAddedContent+'" id="new[content]" /></td>';
+			result += '	   <td><input type="content" size="50" value="'+lastAddedContent.escapeHTML()+'" id="new[content]" /></td>';
 			result += '	   <td><input type="prio" size="2" value="0" id="new[prio]" /"></td>';
 			result += '	   <td><input type="ttl" size="4" value="3600" id="new[ttl]" /></td>';
 			result += '	   <td><input type="button" onclick="newRecord('+jsonData.domain.id+', document.getElementById(\'new[name]\').value, ';
@@ -542,7 +542,7 @@
 			{
 				result += '<tr>';
 				result += '  <td>[ <a onclick="deleteUser('+jsonData[i].id+');setTimeout(\'userAdmin();\', '+timeoutInMilisec+');">delete user</a> ]</td>';
-				result += '  <td><a href="javascript:editUser('+jsonData[i].id+');">'+jsonData[i].fullname+'</a></td>';
+				result += '  <td><a href="javascript:editUser('+jsonData[i].id+');">'+jsonData[i].fullname.escapeHTML()+'</a></td>';
 				result += '  <td>'+jsonData[i].level+'</td>';
 				result += '</tr>';
 			}
@@ -610,11 +610,11 @@
 		if(!editUser_u2ftokens || !editUser_u2ftokens.length) editUser_u2ftokens=[];
 
 		var result = '<h3>Edit user :: <b>'+jsonData.username+'</b></h3><table width="800"><input type="hidden" id="userId" value="'+jsonData.id+'">';
-		result += '<tr><td>Username</td><td><input type="text" id="username" value="'+jsonData.username+'"></td></tr>';
+		result += '<tr><td>Username</td><td><input type="text" id="username" value="'+jsonData.username.escapeHTML()+'"></td></tr>';
 		result += '<tr><td>Password</td><td><input type="password" id="password" value=""></td></tr>';
-		result += '<tr><td>Full name</td><td><input type="text" id="fullname" value="'+jsonData.fullname+'"></td></tr>';
-		result += '<tr><td>E-mail</td><td><input type="text" id="email" value="'+jsonData.email+'"></td></tr>';
-		result += '<tr><td>Description</td><td><textarea id="description">'+jsonData.description+'</textarea></td></tr>';
+		result += '<tr><td>Full name</td><td><input type="text" id="fullname" value="'+jsonData.fullname.escapeHTML()+'"></td></tr>';
+		result += '<tr><td>E-mail</td><td><input type="text" id="email" value="'+jsonData.email.escapeHTML()+'"></td></tr>';
+		result += '<tr><td>Description</td><td><textarea id="description">'+jsonData.description.escapeHTML()+'</textarea></td></tr>';
 		result += '<tr><td>Max domains</td><td colspan="2"><input type="text" id="maxdomains" value="'+jsonData.maxdomains+'"></td></tr>';
 		result += '<tr><td>Level</td><td><input type="text" id="level" value="'+jsonData.level+'"></td></tr>';
 		result += '<tr><td>Active</td><td><input type="text" id="active" value="'+jsonData.active+'"></td></tr>';
@@ -624,7 +624,7 @@
 		for(var i=0; i<editUser_u2ftokens.length; i++) {
 			var token = editUser_u2ftokens[i];
 			result += "<li>";
-			for(var key in token) if (token.hasOwnProperty(key)) result += "<b>"+key+"</b>="+token[key]+"<br>";
+			for(var key in token) if (token.hasOwnProperty(key)) result += "<b>"+key.escapeHTML()+"</b>="+token[key].escapeHTML()+"<br>";
 			result += "<input type='button' value='remove' onclick='removeU2fKey("+i+");'></li>";
 		}
 		result += "</ul>";
```
