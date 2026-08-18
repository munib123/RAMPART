# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1553_3
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1553_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 86-126 of the vulnerable file.

    end

    my_wf_folder = WorkflowsHelper.get_my_wf_folder(@login_user.id)

    sql = WorkflowsHelper.get_list_sql(@login_user.id, my_wf_folder.id)
    @workflows = Workflow.find_by_sql(sql)

    render(:partial => 'ajax_workflow', :layout => false)
  end

  #=== move
  #
  #<Ajax>
  #Moves Workflow to the specified Folder.
  #
  def move
    Log.add_info(request, params.inspect)

    unless params[:thetisBoxSelKeeper].nil?
      folder_id = params[:thetisBoxSelKeeper].split(':').last

      workflow = Workflow.find(params[:id])

      workflow.item.update_attribute(:folder_id, folder_id)

      flash[:notice] = t('msg.move_success')
    end

    my_wf_folder = WorkflowsHelper.get_my_wf_folder(@login_user.id)

    sql = WorkflowsHelper.get_list_sql(@login_user.id, my_wf_folder.id)
    @workflows = Workflow.find_by_sql(sql)

    render(:partial => 'ajax_workflow', :layout => false)

  rescue => evar
    Log.add_error(request, evar)

    flash[:notice] = 'ERROR:' + evar.to_s[0, 64]
    render(:partial => 'ajax_workflow', :layout => false)
  end
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,6 +103,7 @@
 
     unless params[:thetisBoxSelKeeper].nil?
       folder_id = params[:thetisBoxSelKeeper].split(':').last
+      SqlHelper.validate_token([folder_id])
 
       workflow = Workflow.find(params[:id])
 
```
