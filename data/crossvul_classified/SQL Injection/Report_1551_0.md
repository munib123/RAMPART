# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1551_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1551_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 337-379 of the vulnerable file.

  end

  #=== destroy
  #
  #Deletes Item.
  #
  def destroy
    Log.add_info(request, params.inspect)

    return unless request.post?

    begin
      Item.destroy(params[:id])
    rescue => evar
      Log.add_error(request, evar)
    end

    if params[:from_action].nil?
      render(:text => params[:id])
    else
      params.delete(:controller)
      params.delete(:action)
      params.delete(:id)
      flash[:notice] = t('msg.delete_success')
      params[:action] = params[:from_action]
      redirect_to(params)
    end
  end

  #=== destroy_multi
  #
  #Deletes multiple Items.
  #
  def destroy_multi
    Log.add_info(request, params.inspect)

    return unless request.post?

    if params[:check_item].nil?
      list
      render(:action => 'list')
      return
    end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -354,12 +354,8 @@
     if params[:from_action].nil?
       render(:text => params[:id])
     else
-      params.delete(:controller)
-      params.delete(:action)
-      params.delete(:id)
       flash[:notice] = t('msg.delete_success')
-      params[:action] = params[:from_action]
-      redirect_to(params)
+      self.send(params[:from_action])
     end
   end
 
```
