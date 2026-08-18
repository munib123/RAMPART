# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1556_2
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1556_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 19-59 of the vulnerable file.

  validates_presence_of(:name)

  public::BOOK_PRIVATE = 'book_private'
  public::BOOK_COMMON = 'book_common'
  public::BOOK_BOTH = 'book_both'

  public::EXP_IMP_FOR_ALL = 'all'


  #=== self.get_by_email
  #
  #Get an Array of Addresses with specified email.
  #
  #_mail_addr_:: Target E-mail address.
  #_user_:: Target User.
  #_book_:: Book type.
  #return:: Array of Addresses.
  #
  def self.get_by_email(mail_addr, user, book=Address::BOOK_BOTH)

    SqlHelper.validate_token([mail_addr])

    email_con = []
    email_con.push("(email1='#{mail_addr}')")
    email_con.push("(email2='#{mail_addr}')")
    email_con.push("(email3='#{mail_addr}')")
    con = []
    con.push('('+email_con.join(' or ')+')')
    con.push(AddressbookHelper.get_scope_condition_for(user, book))

    return Address.where(con.join(' and ')).to_a
  end

  #=== self.csv_header_cols
  #
  #Gets an Array of CSV header columns.
  #
  #_book_:: Book type.
  #return:: Array of CSV header columns.
  #
  def self.csv_header_cols(book)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -36,12 +36,12 @@
   #
   def self.get_by_email(mail_addr, user, book=Address::BOOK_BOTH)
 
-    SqlHelper.validate_token([mail_addr])
+    mail_quote = SqlHelper.quote(mail_addr)
 
     email_con = []
-    email_con.push("(email1='#{mail_addr}')")
-    email_con.push("(email2='#{mail_addr}')")
-    email_con.push("(email3='#{mail_addr}')")
+    email_con.push("(email1=#{mail_quote})")
+    email_con.push("(email2=#{mail_quote})")
+    email_con.push("(email3=#{mail_quote})")
     con = []
     con.push('('+email_con.join(' or ')+')')
     con.push(AddressbookHelper.get_scope_condition_for(user, book))
@@ -212,7 +212,11 @@
     imp_id = (idxs[0].nil? or row[idxs[0]].nil?)?(nil):(row[idxs[0]].strip)
     SqlHelper.validate_token([imp_id])
     unless imp_id.blank?
-      org_address = Address.find_by_id(imp_id)
+      begin
+        org_address = Address.find(imp_id)
+      rescue => evar
+        org_address = nil
+      end
     end
 
     if org_address.nil?
```
