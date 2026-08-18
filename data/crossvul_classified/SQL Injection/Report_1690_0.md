# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1690_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1690_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 72-112 of the vulnerable file.

      end
    end

    #
    #=== 内部に格納しているパラメータをハッシュ形式で出力する
    #
    def to_s
      attributes.to_s
    end

    #
    #=== フィールドタイプを返す
    #
    def field_type(name)
      self.fields[name.to_sym] ? self.fields[name.to_sym][:type] : nil
    end

    #
    #=== ソート順を返す
    #
    def order_by
      order_option = ''
      if self.order_column
        direction = self.order_direction || 'ASC'
        order_option = "#{self.order_column} #{direction}"
      end
      order_option.present? ? order_option : @@default_order
    end

    private
      #
      #== 日付型のリクエストパラメータを解析する
      #
      def parse_datetime(attr, name)
        _name = name.to_s
        begin
          y = attr[(_name + '(1i)').to_sym].to_i
          m = attr[(_name + '(2i)').to_sym].to_i
          d = attr[(_name + '(3i)').to_sym].to_i

          if field_type(name) == :date
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -89,13 +89,9 @@
     #
     #=== ソート順を返す
     #
+    # 子クラスでオーバーライドすること
+    #
     def order_by
-      order_option = ''
-      if self.order_column
-        direction = self.order_direction || 'ASC'
-        order_option = "#{self.order_column} #{direction}"
-      end
-      order_option.present? ? order_option : @@default_order
     end
 
     private
```
