# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in cpp
**Pair ID:** 2324_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2324_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```cpp
Lines 1-23 of the vulnerable file.

/*

Copyright (c) 2008-2012, Arvid Norberg
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1,6 +1,6 @@
 /*
 
-Copyright (c) 2008-2012, Arvid Norberg
+Copyright (c) 2008-2014, Arvid Norberg
 All rights reserved.
 
 Redistribution and use in source and binary forms, with or without
@@ -45,35 +45,62 @@
 namespace libtorrent
 {
 
-#define TORRENT_FAIL_BDECODE(code) \
-	{ \
-		ec = make_error_code(code); \
-		while (!stack.empty()) { \
-			top = stack.back(); \
-			if (top->type() == lazy_entry::dict_t || top->type() == lazy_entry::list_t) top->pop(); \
-			stack.pop_back(); \
-		} \
-		if (error_pos) *error_pos = start - orig_start; \
-		return -1; \
-	}
-
-	bool is_digit(char c) { return c >= '0' && c <= '9'; }
-
-	bool is_print(char c) { return c >= 32 && c < 127; }
+	namespace
+	{
+		int fail(int* error_pos
+			, std::vector<lazy_entry*>& stack
+			, char const* start
+			, char const* orig_start)
+		{
+			while (!stack.empty()) {
+				lazy_entry* top = stack.back();
+				if (top->type() == lazy_entry::dict_t || top->type() == lazy_entry::list_t)
+				{
+					top->pop();
+					break;
+				}
+				stack.pop_back();
+			}
+			if (error_pos) *error_pos = start - orig_start;
+			return -1;
+		}
+	}
+
+#define TORRENT_FAIL_BDECODE(code) do { ec = make_error_code(code); return fail(error_pos, stack, start, orig_start); } while (false)
+
+	namespace { bool numeric(char c) { return c >= '0' && c <= '9'; } }
 
 	// fills in 'val' with what the string between start and the
 	// first occurance of the delimiter is interpreted as an int.
 	// return the pointer to the delimiter, or 0 if there is a
 	// parse error. val should be initialized to zero
-	char const* parse_int(char const* start, char const* end, char delimiter, boost::int64_t& val)
+	char const* parse_int(char const* start, char const* end, char delimiter
+		, boost::int64_t& val, bdecode_errors::error_code_enum& ec)
 	{
 		while (start < end && *start != delimiter)
 		{
-			if (!is_digit(*start)) { return 0; }
+			if (!numeric(*start))
+			{
+				ec = bdecode_errors::expected_string;
+				return start;
+			}
+			if (val > INT64_MAX / 10)
+			{
+				ec = bdecode_errors::overflow;
+				return start;
+			}
 			val *= 10;
-			val += *start - '0';
+			int digit = *start - '0';
+			if (val > INT64_MAX - digit)
+			{
+				ec = bdecode_errors::overflow;
+				return start;
+			}
+			val += digit;
 			++start;
 		}
+		if (*start != delimiter)
+			ec = bdecode_errors::expected_colon;
 		return start;
 	}
 
@@ -94,7 +121,7 @@
 		std::vector<lazy_entry*> stack;
 
 		stack.push_back(&ret);
-		while (start < end)
+		while (start <= end)
 		{
 			if (stack.empty()) break; // done!
 
@@ -116,11 +143,19 @@
 						stack.pop_back();
 						continue;
 					}
-					if (!is_digit(t)) TORRENT_FAIL_BDECODE(bdecode_errors::expected_string);
+					if (!numeric(t)) TORRENT_FAIL_BDECODE(bdecode_errors::expected_string);
 					boost::int64_t len = t - '0';
-					start = parse_int(start, end, ':', len);
-					if (start == 0 || start + len + 3 > end || *start != ':')
-						TORRENT_FAIL_BDECODE(bdecode_errors::expected_colon);
+					bdecode_errors::error_code_enum e = bdecode_errors::no_error;
+					start = parse_int(start, end, ':', len, e);
+					if (e)
+						TORRENT_FAIL_BDECODE(e);
+
+					if (start + len + 1 > end)
+						TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
+
+					if (len < 0)
+						TORRENT_FAIL_BDECODE(bdecode_errors::overflow);
+
 					++start;
 					if (start == end) TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
 					lazy_entry* ent = top->dict_append(start);
@@ -173,13 +208,19 @@
 				}
 				default:
 				{
-					if (!is_digit(t))
+					if (!numeric(t))
 						TORRENT_FAIL_BDECODE(bdecode_errors::expected_value);
 
 					boost::int64_t len = t - '0';
-					start = parse_int(start, end, ':', len);
-					if (start == 0 || start + len + 1 > end || *start != ':')
-						TORRENT_FAIL_BDECODE(bdecode_errors::expected_colon);
+					bdecode_errors::error_code_enum e = bdecode_errors::no_error;
+					start = parse_int(start, end, ':', len, e);
+					if (e)
+						TORRENT_FAIL_BDECODE(e);
+					if (start + len + 1 > end)
+						TORRENT_FAIL_BDECODE(bdecode_errors::unexpected_eof);
+					if (len < 0)
+						TORRENT_FAIL_BDECODE(bdecode_errors::overflow);
+
 					++start;
 					top->construct_string(start, int(len));
 					stack.pop_back();
@@ -198,7 +239,10 @@
 		boost::int64_t val = 0;
 		bool negative = false;
 		if (*m_data.start == '-') negative = true;
-		parse_int(negative?m_data.start+1:m_data.start, m_data.start + m_size, 'e', val);
+		bdecode_errors::error_code_enum ec = bdecode_errors::no_error;
+		parse_int(m_data.start + negative
+			, m_data.start + m_size, 'e', val, ec);
+		if (ec) return 0;
 		if (negative) val = -val;
 		return val;
 	}
@@ -331,6 +375,13 @@
 		return e;
 	}
 
+	lazy_entry const* lazy_entry::dict_find_dict(std::string const& name) const
+	{
+		lazy_entry const* e = dict_find(name);
+		if (e == 0 || e->type() != lazy_entry::dict_t) return 0;
+		return e;
+	}
+
 	lazy_entry const* lazy_entry::dict_find_list(char const* name) const
 	{
 		lazy_entry const* e = dict_find(name);
@@ -345,6 +396,19 @@
 		{
 			lazy_dict_entry& e = m_data.dict[i];
 			if (string_equal(name, e.name, e.val.m_begin - e.name))
+				return &e.val;
+		}
+		return 0;
+	}
+
+	lazy_entry* lazy_entry::dict_find(std::string const& name)
+	{
+		TORRENT_ASSERT(m_type == dict_t);
+		for (int i = 0; i < int(m_size); ++i)
+		{
+			lazy_dict_entry& e = m_data.dict[i];
+			if (name.size() != e.val.m_begin - e.name) continue;
+			if (std::equal(name.begin(), name.end(), e.name))
 				return &e.val;
 		}
 		return 0;
@@ -492,23 +556,50 @@
 				char const* str = e.string_ptr();
 				for (int i = 0; i < e.string_length(); ++i)
 				{
-					using namespace std;
-					if (is_print((unsigned char)str[i])) continue;
+					char c = str[i];
+					if (c >= 32 && c < 127) continue;
 					printable = false;
 					break;
 				}
 				ret += "'";
 				if (printable)
 				{
-					ret += e.string_value();
+					if (single_line && e.string_length() > 30)
+					{
+						ret.append(e.string_ptr(), 14);
+						ret += "...";
+						ret.append(e.string_ptr() + e.string_length()-14, 14);
+					}
+					else
+						ret.append(e.string_ptr(), e.string_length());
 					ret += "'";
 					return ret;
 				}
-				for (int i = 0; i < e.string_length(); ++i)
-				{
-					char tmp[5];
-					snprintf(tmp, sizeof(tmp), "%02x", (unsigned char)str[i]);
-					ret += tmp;
+				if (single_line && e.string_length() > 20)
+				{
+					for (int i = 0; i < 9; ++i)
+					{
+						char tmp[5];
+						snprintf(tmp, sizeof(tmp), "%02x", (unsigned char)str[i]);
+						ret += tmp;
+					}
+					ret += "...";
+					for (int i = e.string_length() - 9
+						, len(e.string_length()); i < len; ++i)
+					{
+						char tmp[5];
+						snprintf(tmp, sizeof(tmp), "%02x", (unsigned char)str[i]);
+						ret += tmp;
+					}
+				}
+				else
+				{
+					for (int i = 0; i < e.string_length(); ++i)
+					{
+						char tmp[5];
+						snprintf(tmp, sizeof(tmp), "%02x", (unsigned char)str[i]);
+						ret += tmp;
+					}
 				}
 				ret += "'";
 				return ret;
@@ -577,6 +668,7 @@
 			"expected value (list, dict, int or string) in bencoded string",
 			"bencoded nesting depth exceeded",
 			"bencoded item count limit exceeded",
+			"integer overflow",
 		};
 		if (ev < 0 || ev >= int(sizeof(msgs)/sizeof(msgs[0])))
 			return "Unknown error";
@@ -589,5 +681,12 @@
 		return bdecode_category;
 	}
 
+	namespace bdecode_errors
+	{
+		boost::system::error_code make_error_code(error_code_enum e)
+		{
+			return boost::system::error_code(e, get_bdecode_category());
+		}
+	}
 };
 
```
