# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 1689_1
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1689_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 237-277 of the vulnerable file.

      #=== 検索フォームモデル
      #
      class PageSearchForm < Susanoo::SearchForm
        attr_accessor :genre

        field :keyword, type: :string
        field :start_at, type: :date
        field :end_at, type: :date
        field :admission, type: :integer
        field :recursive, type: :string
        field :include_copy, type: :string

        @@default_order =  'pages.name ASC'

        def initialize(attr = {})
          attr[:order_column] ||= 'pages.name'
          attr[:order_direction] ||= 'ASC'
          super
        end


        #
        #=== 検索を実施する
        #
        def search(user, genre)
          order = order_by
          result = Page.search(genre, attributes, {order_column: order_column, user: user})
          result = result.order(order) if order.present?
          result
        end

        #
        #=== 公開日ソート可否判定
        # 公開中、公開期間が指定された場合のみソート可能
        #
        def last_modified_sortable?
          s = PageContent.page_status
          if [s[:publish],s[:finished],s[:cancel]].include?(admission) ||
            begin_at.present? || end_at.present?
            true
          else
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -254,7 +254,6 @@
           super
         end
 
-
         #
         #=== 検索を実施する
         #
@@ -278,7 +277,43 @@
             false
           end
         end
-      end
+
+        #
+        #=== ソート順を返す
+        #
+        def order_by
+          order_option = ''
+          if valid_order_params?
+            direction = self.order_direction || 'ASC'
+            order_option = "#{self.order_column} #{direction}"
+          end
+          order_option.present? ? order_option : @@default_order
+        end
+
+        #
+        #=== ソートパラメータを検証する
+        #
+        def valid_order_params?
+          if self.order_column.blank?
+            return false
+          end
+
+          permit_column_params = ['pages.name', 'page_contents.last_modified']
+          permit_dir_params = ['ASC', 'DESC']
+
+          unless permit_column_params.include?(self.order_column)
+            return false
+          end
+
+          if self.order_direction.present? &&
+            !permit_dir_params.include?(self.order_direction.upcase)
+            return false
+          end
+
+          return true
+        end
+      end
+
   end
 end
 
```
