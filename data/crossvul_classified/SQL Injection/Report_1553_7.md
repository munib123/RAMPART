# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1553_7
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1553_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 36-76 of the vulnerable file.


  public::ADDR_PREFIX_SEPARATOR = ':'
  public::ADDR_PREFIX_TO = 'To'+ADDR_PREFIX_SEPARATOR
  public::ADDR_PREFIX_CC = 'Cc'+ADDR_PREFIX_SEPARATOR
  public::ADDR_PREFIX_BCC = 'Bcc'+ADDR_PREFIX_SEPARATOR

  public::EXT_RAW = '.eml'


  before_save do |email|

# FEATURE_MAIL_STRICT_CAPACITY >>>
    org_size = (email.size || 0)
# FEATURE_MAIL_STRICT_CAPACITY <<<

    email.recalc_size

# FEATURE_MAIL_STRICT_CAPACITY >>>
    if (email.status != Email::STATUS_TEMPORARY) \
        and (email.size > org_size)
      mail_account = MailAccount.find_by_id(email.mail_account_id)
      max_size = mail_account.get_capacity_mb * 1024 * 1024
      con = "(id != #{email.id})" unless email.id.nil?
      cur_size = MailAccount.get_using_size(mail_account.id, con)
      if email.size > (max_size - cur_size)
        raise('ERROR:' + I18n.t('mail.msg.capacity_over'))
      end
    end
# FEATURE_MAIL_STRICT_CAPACITY <<<
  end

  #=== unread?
  #
  #Gets whether this E-mail is unread or not.
  #
  #return:: true if this E-mail is unread, false otherwise.
  #
  def unread?
    return (self.status == Email::STATUS_UNREAD)
  end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -53,7 +53,7 @@
 # FEATURE_MAIL_STRICT_CAPACITY >>>
     if (email.status != Email::STATUS_TEMPORARY) \
         and (email.size > org_size)
-      mail_account = MailAccount.find_by_id(email.mail_account_id)
+      mail_account = MailAccount.find(email.mail_account_id)
       max_size = mail_account.get_capacity_mb * 1024 * 1024
       con = "(id != #{email.id})" unless email.id.nil?
       cur_size = MailAccount.get_using_size(mail_account.id, con)
```
