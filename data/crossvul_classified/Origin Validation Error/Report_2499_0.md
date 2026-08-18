# CrossVul Fix Pair: Origin Validation Error in ruby
**Pair ID:** 2499_0
**Vulnerability Class:** Origin Validation Error
**CWE:** CWE-346
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2499_0`)

## Vulnerability Information & PoC

## Description
Origin Validation Error - The product does not properly verify that the source of data or communication is valid.

## Vulnerable Code
```ruby
Lines 93-133 of the vulnerable file.

    @dns = dns
    @headers = headers
  end

  ##
  # Given a source at +uri+, calculate what hostname to actually
  # connect to query the data for it.

  def api_endpoint(uri)
    host = uri.host

    begin
      res = @dns.getresource "_rubygems._tcp.#{host}",
                             Resolv::DNS::Resource::IN::SRV
    rescue Resolv::ResolvError => e
      verbose "Getting SRV record failed: #{e}"
      uri
    else
      target = res.target.to_s.strip

      if /\.#{Regexp.quote(host)}\z/ =~ target
        return URI.parse "#{uri.scheme}://#{target}#{uri.path}"
      end

      uri
    end
  end

  ##
  # Given a name and requirement, downloads this gem into cache and returns the
  # filename. Returns nil if the gem cannot be located.
  #--
  # Should probably be integrated with #download below, but that will be a
  # larger, more encompassing effort. -erikh

  def download_to_cache dependency
    found, _ = Gem::SpecFetcher.fetcher.spec_for_dependency dependency

    return if found.empty?

    spec, source = found.max_by { |(s,_)| s.version }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -110,7 +110,7 @@
     else
       target = res.target.to_s.strip
 
-      if /\.#{Regexp.quote(host)}\z/ =~ target
+      if URI("http://" + target).host.end_with?(".#{host}")
         return URI.parse "#{uri.scheme}://#{target}#{uri.path}"
       end
 
```
