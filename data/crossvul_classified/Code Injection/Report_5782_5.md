# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 5782_5
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5782_5`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 98-138 of the vulnerable file.

        @filter_users  = User.where(id: @environment.bugs.select('assigned_user_id').uniq.limit(PER_PAGE).map(&:assigned_user_id)).order('username ASC')
        # index.html.rb
      end

      format.json do
        filter = (params[:filter] || {}).slice(*VALID_FILTER_KEYS)
        filter.each { |k, v| filter[k] = nil if v == '' }

        filter.delete('deploy_id') if filter['deploy_id'].nil? # no deploy set means ANY deploy, not NO deploy
        filter.delete('any_occurrence_crashed') if filter['any_occurrence_crashed'].nil?

        # sentinel values
        filter.delete('assigned_user_id') if filter['assigned_user_id'] == 'somebody'
        filter.delete('assigned_user_id') if filter['assigned_user_id'] == 'anybody'
        filter['assigned_user_id'] = nil if filter['assigned_user_id'] == 'nobody'
        query = filter.delete('search')

        sort_column, default_dir = SORTS[params[:sort]]

        dir = if params[:dir].kind_of?(String) then
                SORT_DIRECTIONS.include?(params[:dir].upcase) ? params[:dir] : default_dir
              else
                default_dir
              end

        @bugs = @environment.bugs.where(filter).order("#{sort_column} #{dir}, bugs.number #{dir}").limit(PER_PAGE)
        @bugs = @bugs.where('assigned_user_id IS NOT NULL') if params[:filter] && params[:filter][:assigned_user_id] == 'somebody'
        @bugs = @bugs.query(query) if query.present?

        last = params[:last].present? ? @environment.bugs.find_by_number(params[:last]) : nil
        @bugs = @bugs.where(infinite_scroll_clause(sort_column, dir, last, 'bugs.number')) if last

        begin
          render json: decorate_bugs(@bugs)
        rescue => err
          if (err.kind_of?(ActiveRecord::StatementInvalid) ||
              (defined?(ActiveRecord::JDBCError) && err.kind_of?(ActiveRecord::JDBCError))) &&
              err.to_s =~ /syntax error in tsquery/
            head :unprocessable_entity
          else
            raise
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -115,7 +115,7 @@
         sort_column, default_dir = SORTS[params[:sort]]
 
         dir = if params[:dir].kind_of?(String) then
-                SORT_DIRECTIONS.include?(params[:dir].upcase) ? params[:dir] : default_dir
+                SORT_DIRECTIONS.include?(params[:dir].upcase) ? params[:dir].upcase : default_dir
               else
                 default_dir
               end
```
