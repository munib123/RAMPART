# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') in ruby
**Pair ID:** 4651_0
**Vulnerability Class:** SQL Injection
**CWE:** CWE-89
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4651_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') - Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.

## Vulnerable Code
```ruby
Lines 27-67 of the vulnerable file.

    # rather than a circle, so results are very approximate (will include
    # objects outside the given radius).
    #
    # Distance and bearing calculations are *extremely inaccurate*. To be
    # clear: this only exists to provide interface consistency. Results
    # are not intended for use in production!
    #
    def approx_distance(latitude, longitude, lat_attr, lon_attr, options = {})
      units = options[:units] || Geocoder.config.units
      dx = Geocoder::Calculations.longitude_degree_distance(30, units)
      dy = Geocoder::Calculations.latitude_degree_distance(units)

      # sin of 45 degrees = average x or y component of vector
      factor = Math.sin(Math::PI / 4)

      "(#{dy} * ABS(#{lat_attr} - #{latitude.to_f}) * #{factor}) + " +
        "(#{dx} * ABS(#{lon_attr} - #{longitude.to_f}) * #{factor})"
    end

    def within_bounding_box(sw_lat, sw_lng, ne_lat, ne_lng, lat_attr, lon_attr)
      spans = "#{lat_attr} BETWEEN #{sw_lat} AND #{ne_lat} AND "
      # handle box that spans 180 longitude
      if sw_lng.to_f > ne_lng.to_f
        spans + "(#{lon_attr} BETWEEN #{sw_lng} AND 180 OR " +
        "#{lon_attr} BETWEEN -180 AND #{ne_lng})"
      else
        spans + "#{lon_attr} BETWEEN #{sw_lng} AND #{ne_lng}"
      end
    end

    ##
    # Fairly accurate bearing calculation. Takes a latitude, longitude,
    # and an options hash which must include a :bearing value
    # (:linear or :spherical).
    #
    # For use with a database that supports MOD() and trigonometric functions
    # SIN(), COS(), ASIN(), ATAN2().
    #
    # Based on:
    # http://www.beginningspatial.com/calculating_bearing_one_point_another
    #
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -44,13 +44,13 @@
     end
 
     def within_bounding_box(sw_lat, sw_lng, ne_lat, ne_lng, lat_attr, lon_attr)
-      spans = "#{lat_attr} BETWEEN #{sw_lat} AND #{ne_lat} AND "
+      spans = "#{lat_attr} BETWEEN #{sw_lat.to_f} AND #{ne_lat.to_f} AND "
       # handle box that spans 180 longitude
       if sw_lng.to_f > ne_lng.to_f
-        spans + "(#{lon_attr} BETWEEN #{sw_lng} AND 180 OR " +
-        "#{lon_attr} BETWEEN -180 AND #{ne_lng})"
+        spans + "(#{lon_attr} BETWEEN #{sw_lng.to_f} AND 180 OR " +
+        "#{lon_attr} BETWEEN -180 AND #{ne_lng.to_f})"
       else
-        spans + "#{lon_attr} BETWEEN #{sw_lng} AND #{ne_lng}"
+        spans + "#{lon_attr} BETWEEN #{sw_lng.to_f} AND #{ne_lng.to_f}"
       end
     end
 
```
