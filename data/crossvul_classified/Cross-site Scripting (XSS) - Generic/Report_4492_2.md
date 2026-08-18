# CrossVul Fix Pair: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') in ruby
**Pair ID:** 4492_2
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**CWE:** CWE-79
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4492_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Cross-site scripting (XSS) vulnerabilities occur when: Untrusted data enters a web application, typically from a web request.

## Vulnerable Code
```ruby
Lines 194-234 of the vulnerable file.

          /<a[^>]* class="remove_nested_fields"[^>]*>/,
        )
      end
    end

    context "when a field which have the same name of nested_in field's" do
      it "does not hide fields which are not associated with nesting parent field's model" do
        visit new_path(model_name: 'field_test')
        is_expected.not_to have_selector('select#field_test_nested_field_tests_attributes_new_nested_field_tests_field_test_id')
        expect(find('div#nested_field_tests_fields_blueprint', visible: false)[:'data-blueprint']).to match(
          /<select[^>]* id="field_test_nested_field_tests_attributes_new_nested_field_tests_another_field_test_id"[^>]*>/,
        )
      end

      it 'hides fields that are deeply nested with inverse_of' do
        visit new_path(model_name: 'field_test')
        expect(page.body).to_not include('field_test_nested_field_tests_attributes_new_nested_field_tests_deeply_nested_field_tests_attributes_new_deeply_nested_field_tests_nested_field_test_id_field')
        expect(page.body).to include('field_test_nested_field_tests_attributes_new_nested_field_tests_deeply_nested_field_tests_attributes_new_deeply_nested_field_tests_title')
      end
    end
  end

  context 'with not nullable foreign key', active_record: true do
    before do
      RailsAdmin.config FieldTest do
        edit do
          field :nested_field_tests do
            nested_form false
          end
        end
      end
      @field_test = FactoryBot.create :field_test
    end

    it 'don\'t allow to remove element', js: true do
      visit edit_path(model_name: 'FieldTest', id: @field_test.id)
      is_expected.not_to have_selector('a.ra-multiselect-item-remove')
      is_expected.not_to have_selector('a.ra-multiselect-item-remove-all')
    end
  end

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -211,6 +211,22 @@
         expect(page.body).to include('field_test_nested_field_tests_attributes_new_nested_field_tests_deeply_nested_field_tests_attributes_new_deeply_nested_field_tests_title')
       end
     end
+
+    context 'when XSS attack is attempted', js: true do
+      it 'does not break on adding a new item' do
+        allow(I18n).to receive(:t).and_call_original
+        expect(I18n).to receive(:t).with('admin.form.new_model', name: 'Nested field test').and_return('<script>throw "XSS";</script>')
+        @record = FactoryBot.create :field_test
+        visit edit_path(model_name: 'field_test', id: @record.id)
+        find('#field_test_nested_field_tests_attributes_field .add_nested_fields').click
+      end
+
+      it 'does not break on editing an existing item' do
+        @record = FactoryBot.create :field_test
+        NestedFieldTest.create! title: '<script>throw "XSS";</script>', field_test: @record
+        visit edit_path(model_name: 'field_test', id: @record.id)
+      end
+    end
   end
 
   context 'with not nullable foreign key', active_record: true do
```
