# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1553_5
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1553_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 193-233 of the vulnerable file.

  #return:: Array of error header names.
  #
  def self.check_csv_header(row, book)

    return (row - Address.csv_header_cols(book))
  end

  #=== self.parse_csv_row
  #
  #Parses fields array of a CSV row.
  #
  #_row_:: Fields array of a CSV row.
  #_book_:: Book type.
  #_idxs_:: Array of header column indexes.
  #_user_:: Subjective User.
  #return:: Address instance created from specified array.
  #
  def self.parse_csv_row(row, book, idxs, user)

    imp_id = (idxs[0].nil? or row[idxs[0]].nil?)?(nil):(row[idxs[0]].strip)
    unless imp_id.nil? or imp_id.empty?
      org_address = Address.find_by_id(imp_id)
    end

    if org_address.nil?
      address = Address.new
    else
      address = org_address
    end

    address.id = imp_id
    attr_names = [
      :name,
      :name_ruby,
      :nickname,
      :screenname,
      :email1,
      :email2,
      :email3,
      :postalcode,
      :address,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -210,7 +210,8 @@
   def self.parse_csv_row(row, book, idxs, user)
 
     imp_id = (idxs[0].nil? or row[idxs[0]].nil?)?(nil):(row[idxs[0]].strip)
-    unless imp_id.nil? or imp_id.empty?
+    SqlHelper.validate_token([imp_id])
+    unless imp_id.blank?
       org_address = Address.find_by_id(imp_id)
     end
 
@@ -305,7 +306,11 @@
       if (/^|([0-9]+|)+$/ =~ self.groups) == 0
 
         self.get_groups_a.each do |group_id|
-          group = Group.find_by_id(group_id)
+          begin
+            group = Group.find(group_id)
+          rescue => evar
+            group = nil
+          end
           if group.nil?
             err_msgs << I18n.t('address.import.not_valid_groups') + ': '+group_id.to_s
             break
@@ -322,7 +327,11 @@
       if (/^|([0-9]+|)+$/ =~ self.teams) == 0
 
         self.get_teams_a.each do |team_id|
-          team = Team.find_by_id(team_id)
+          begin
+            team = Team.find(team_id)
+          rescue => evar
+            team = nil
+          end
           if team.nil?
             err_msgs << I18n.t('address.import.not_valid_teams') + ': '+team_id.to_s
             break
```
