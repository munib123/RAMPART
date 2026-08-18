# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in javascript
**Pair ID:** 3746_0
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** javascript
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3746_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```javascript
Lines 40-81 of the vulnerable file.

				button.parent().children('ul').slideUp(400,function(){
					button.parent().children('ul').remove();
					button.removeClass('active');
				});
				return;
			}
			var lists=$('ul.multiselectoptions');
			lists.slideUp(400,function(){
				lists.remove();
				$('div.multiselect').removeClass('active');
				button.addClass('active');
			});
			button.addClass('active');
			event.stopPropagation();
			var options=$(this).parent().next().children();
			var list=$('<ul class="multiselectoptions"/>').hide().appendTo($(this).parent());
			function createItem(element,checked){
				element=$(element);
				var item=element.val();
				var id='ms'+multiSelectId+'-option-'+item;
				var input=$('<input id="'+id+'" type="checkbox"/>');
				var label=$('<label for="'+id+'">'+item+'</label>');
				if(settings.checked.indexOf(item)!=-1 || checked){
					input.attr('checked',true);
				}
				if(checked){
					settings.checked.push(item);
				}
				input.change(function(){
					var groupname=$(this).next().text();
					if($(this).is(':checked')){
						element.attr('selected','selected');
						if(settings.oncheck){
							if(settings.oncheck(groupname)===false){
								$(this).attr('checked', false);
								return;
							}
						}
						settings.checked.push(groupname);
					}else{
						var index=settings.checked.indexOf(groupname);
						element.attr('selected',null);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -57,8 +57,11 @@
 				element=$(element);
 				var item=element.val();
 				var id='ms'+multiSelectId+'-option-'+item;
-				var input=$('<input id="'+id+'" type="checkbox"/>');
-				var label=$('<label for="'+id+'">'+item+'</label>');
+				var input=$('<input type="checkbox"/>');
+				input.attr('id',id);
+				var label=$('<label/>');
+				label.attr('for',id);
+				label.text(item);
 				if(settings.checked.indexOf(item)!=-1 || checked){
 					input.attr('checked',true);
 				}
@@ -130,7 +133,10 @@
 							li.text('+ '+settings.createText);
 							li.before(createItem(this));
 							var select=button.parent().next();
-							select.append($('<option selected="selected" value="'+$(this).val()+'">'+$(this).val()+'</option>'));
+							var option=$('<option selected="selected"/>');
+							option.attr('value',$(this).val());
+							option.text($(this).val());
+							select.append(optione);
 							li.prev().children('input').trigger('click');
 							button.parent().data('preventHide',false);
 							if(settings.createCallback){
```
