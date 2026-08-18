# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1552_6
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1552_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 417-457 of the vulnerable file.

  #
  def edit_page

    # Saved contents of Login User
    begin
      @research = Research.where("user_id=#{@login_user.id}").first
    rescue
    end
    if @research.nil?
      @research = Research.new
    else
      # Already accepted?
      if !@research.status.nil? and @research.status != 0
        render(:action => 'show_receipt')
        return
      end
    end

    # Specifying page
    @page = '01'
    unless params[:page].nil? or params[:page].empty?
      @page = params[:page]
    end
  end

  #=== save_page
  #
  #Saves current page and shows next or receipt-page.
  #
  def save_page
    Log.add_info(request, params.inspect)

    # Next page
    pave_val = params[:page].to_i + 1
    @page = sprintf('%02d', pave_val)

    page_num = Dir.glob(File.join(Research.page_dir, "_q[0-9][0-9].html.erb")).length

    unless params[:research].nil?
      params[:research].each do |key, value|
        if value.instance_of?(Array)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -434,8 +434,9 @@
 
     # Specifying page
     @page = '01'
-    unless params[:page].nil? or params[:page].empty?
+    unless params[:page].blank?
       @page = params[:page]
+      SqlHelper.validate_token([@page])
     end
   end
 
@@ -466,12 +467,14 @@
       end
     end
 
-    if params[:research_id].nil? or params[:research_id].empty?
+    research_id = params[:research_id]
+    SqlHelper.validate_token([research_id])
+    if research_id.blank?
       @research = Research.new(params.require(:research).permit(Research::PERMIT_BASE))
       @research.status = Research::U_STATUS_IN_ACTON
       @research.update_attribute(:user_id, @login_user.id)
     else
-      @research = Research.find(params[:research_id])
+      @research = Research.find(research_id)
       @research.update_attributes(params.require(:research).permit(Research::PERMIT_BASE))
     end
 
@@ -552,6 +555,8 @@
     elsif !params[:group_id].blank?
       @group_id = params[:group_id]
     end
+    SqlHelper.validate_token([@group_id])
+
     unless @group_id.nil?
       con << SqlHelper.get_sql_like([:groups], "|#{@group_id}|")
     end
@@ -690,6 +695,7 @@
 
     unless params[:thetisBoxSelKeeper].nil?
       @group_id = params[:thetisBoxSelKeeper].split(':').last
+      SqlHelper.validate_token([@group_id])
 
       group_cons = []
 
```
