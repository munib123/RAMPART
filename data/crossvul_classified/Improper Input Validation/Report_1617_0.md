# CrossVul Fix Pair: Improper Input Validation in ruby
**Pair ID:** 1617_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** ruby
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1617_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```ruby
Lines 79-119 of the vulnerable file.

    @cert_files = Gem::Request.get_cert_files

    @dns = dns
  end

  ##
  # Given a source at +uri+, calculate what hostname to actually
  # connect to query the data for it.

  def api_endpoint(uri)
    host = uri.host

    begin
      res = @dns.getresource "_rubygems._tcp.#{host}",
                             Resolv::DNS::Resource::IN::SRV
    rescue Resolv::ResolvError
      uri
    else
      target = res.target.to_s.strip

      if /#{host}\z/ =~ target
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
@@ -96,7 +96,7 @@
     else
       target = res.target.to_s.strip
 
-      if /#{host}\z/ =~ target
+      if /\.#{Regexp.quote(host)}\z/ =~ target
         return URI.parse "#{uri.scheme}://#{target}#{uri.path}"
       end
 
```
