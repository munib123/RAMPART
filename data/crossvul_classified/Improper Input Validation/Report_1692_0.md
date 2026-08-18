# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 1692_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1692_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 133-173 of the vulnerable file.

			++start;
			if (start >= end && t != 'e') TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);

			switch (top->type())
			{
				case lazy_entry::dict_t:
				{
					if (t == 'e')
					{
						top->set_end(start);
						stack.pop_back();
						continue;
					}
					if (!numeric(t)) TORRENT_FAIL_BDECODE(bdecode_errors::expected_string);
					boost::int64_t len = t - '0';
					bdecode_errors::error_code_enum e = bdecode_errors::no_error;
					start = parse_int(start, end, ':', len, e);
					if (e)
						TORRENT_FAIL_BDECODE(e);

					if (start + len + 1 > end)
						TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);

					if (len < 0)
						TORRENT_FAIL_BDECODE(bdecode_errors::overflow);

					++start;
					if (start == end) TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
					lazy_entry* ent = top->dict_append(start);
					if (ent == 0) TORRENT_FAIL_BDECODE(boost::system::errc::not_enough_memory);
					start += len;
					if (start >= end) TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
					stack.push_back(ent);
					t = *start;
					++start;
					break;
				}
				case lazy_entry::list_t:
				{
					if (t == 'e')
					{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -150,7 +150,9 @@
 					if (e)
 						TORRENT_FAIL_BDECODE(e);
 
-					if (start + len + 1 > end)
+					// remaining buffer size excluding ':'
+					const ptrdiff_t buff_size = end - start - 1;
+					if (len > buff_size)
 						TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
 
 					if (len < 0)
@@ -216,12 +218,16 @@
 					start = parse_int(start, end, ':', len, e);
 					if (e)
 						TORRENT_FAIL_BDECODE(e);
-					if (start + len + 1 > end)
+
+					// remaining buffer size excluding ':'
+					const ptrdiff_t buff_size = end - start - 1;
+					if (len > buff_size)
 						TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
 					if (len < 0)
 						TORRENT_FAIL_BDECODE(bdecode_errors::overflow);
 
 					++start;
+					if (start == end) TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
 					top->construct_string(start, int(len));
 					stack.pop_back();
 					start += len;
```
