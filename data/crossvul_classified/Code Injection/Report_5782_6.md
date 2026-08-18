# CrossVul Fix Pair: Improper Control of Generation of Code ('Code Injection') in ruby
**Pair ID:** 5782_6
**Vulnerability Class:** Code Injection
**CWE:** CWE-94
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5782_6`)

## Vulnerability Information & PoC

## Description
Improper Control of Generation of Code ('Code Injection') - When a product allows a user's input to contain code syntax, it might be possible for an attacker to craft the code in such a way that it will alter the intended control flow of the product.

## Vulnerable Code
```ruby
Lines 71-111 of the vulnerable file.

  # ----------------
  #
  # |        |                                                                                                                  |
  # |:-------|:-----------------------------------------------------------------------------------------------------------------|
  # | `last` | The number of the last Occurrence of the previous page; used to determine the start of the next page (optional). |
  #
  # Atom
  # ====
  #
  # Returns a feed of the most recent Occurrences of a Bug.
  #
  # Routes
  # ------
  #
  # * `GET /projects/:project_id/environments/:environment_id/bugs/:bug_id/occurrences.atom`

  def index
    respond_to do |format|
      format.json do
        dir = params[:dir]
        dir = 'desc' unless SORT_DIRECTIONS.include?(dir.try(:upcase))

        @occurrences = @bug.occurrences.order("occurred_at #{dir}").limit(50)

        last = params[:last].present? ? @bug.occurrences.find_by_number(params[:last]) : nil
        @occurrences = @occurrences.where(infinite_scroll_clause('occurred_at', dir, last, 'occurrences.number')) if last

        render json: decorate(@occurrences)
      end
      format.atom { @occurrences = @bug.occurrences.order('occurred_at DESC').limit(100) } # index.atom.builder
    end
  end

  # Returns aggregate information about Occurrences across up to four
  # dimensions. Values are aggregated by time and partitioned by dimension value
  # combinations.
  #
  # A time range must be specified. Regardless of the time range, only up to a
  # maximum of {MAX_AGGREGATED_RECORDS} is loaded.
  #
  # Routes
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -88,7 +88,7 @@
     respond_to do |format|
       format.json do
         dir = params[:dir]
-        dir = 'desc' unless SORT_DIRECTIONS.include?(dir.try(:upcase))
+        dir = 'DESC' unless SORT_DIRECTIONS.include?(dir.try(:upcase))
 
         @occurrences = @bug.occurrences.order("occurred_at #{dir}").limit(50)
 
```
