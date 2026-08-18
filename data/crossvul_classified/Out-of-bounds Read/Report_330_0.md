# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 330_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `330_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 513-553 of the vulnerable file.

static const struct tok dccp_option_values[] = {
	{ 0, "nop" },
	{ 1, "mandatory" },
	{ 2, "slowreceiver" },
	{ 32, "change_l" },
	{ 33, "confirm_l" },
	{ 34, "change_r" },
	{ 35, "confirm_r" },
	{ 36, "initcookie" },
	{ 37, "ndp_count" },
	{ 38, "ack_vector0" },
	{ 39, "ack_vector1" },
	{ 40, "data_dropped" },
	{ 41, "timestamp" },
	{ 42, "timestamp_echo" },
	{ 43, "elapsed_time" },
	{ 44, "data_checksum" },
	{ 0, NULL }
};

static int dccp_print_option(netdissect_options *ndo, const u_char *option, u_int hlen)
{
	uint8_t optlen, i;

	ND_TCHECK(*option);

	if (*option >= 32) {
		ND_TCHECK(*(option+1));
		optlen = *(option +1);
		if (optlen < 2) {
			if (*option >= 128)
				ND_PRINT((ndo, "CCID option %u optlen too short", *option));
			else
				ND_PRINT((ndo, "%s optlen too short",
					  tok2str(dccp_option_values, "Option %u", *option)));
			return 0;
		}
	} else
		optlen = 1;

	if (hlen < optlen) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -530,7 +530,8 @@
 	{ 0, NULL }
 };
 
-static int dccp_print_option(netdissect_options *ndo, const u_char *option, u_int hlen)
+static int
+dccp_print_option(netdissect_options *ndo, const u_char *option, u_int hlen)
 {
 	uint8_t optlen, i;
 
@@ -623,16 +624,54 @@
 			}
 			break;
 		case 41:
-			if (optlen == 4)
+		/*
+		 * 13.1.  Timestamp Option
+		 *
+		 *  +--------+--------+--------+--------+--------+--------+
+		 *  |00101001|00000110|          Timestamp Value          |
+		 *  +--------+--------+--------+--------+--------+--------+
+		 *   Type=41  Length=6
+		 */
+			if (optlen == 6)
 				ND_PRINT((ndo, " %u", EXTRACT_32BITS(option + 2)));
 			else
-				ND_PRINT((ndo, " optlen != 4"));
+				ND_PRINT((ndo, " [optlen != 6]"));
 			break;
 		case 42:
-			if (optlen == 4)
+		/*
+		 * 13.3.  Timestamp Echo Option
+		 *
+		 *  +--------+--------+--------+--------+--------+--------+
+		 *  |00101010|00000110|           Timestamp Echo          |
+		 *  +--------+--------+--------+--------+--------+--------+
+		 *   Type=42    Len=6
+		 *
+		 *  +--------+--------+------- ... -------+--------+--------+
+		 *  |00101010|00001000|  Timestamp Echo   |   Elapsed Time  |
+		 *  +--------+--------+------- ... -------+--------+--------+
+		 *   Type=42    Len=8       (4 bytes)
+		 *
+		 *  +--------+--------+------- ... -------+------- ... -------+
+		 *  |00101010|00001010|  Timestamp Echo   |    Elapsed Time   |
+		 *  +--------+--------+------- ... -------+------- ... -------+
+		 *   Type=42   Len=10       (4 bytes)           (4 bytes)
+		 */
+			switch (optlen) {
+			case 6:
 				ND_PRINT((ndo, " %u", EXTRACT_32BITS(option + 2)));
-			else
-				ND_PRINT((ndo, " optlen != 4"));
+				break;
+			case 8:
+				ND_PRINT((ndo, " %u", EXTRACT_32BITS(option + 2)));
+				ND_PRINT((ndo, " (elapsed time %u)", EXTRACT_16BITS(option + 6)));
+				break;
+			case 10:
+				ND_PRINT((ndo, " %u", EXTRACT_32BITS(option + 2)));
+				ND_PRINT((ndo, " (elapsed time %u)", EXTRACT_32BITS(option + 6)));
+				break;
+			default:
+				ND_PRINT((ndo, " [optlen != 6 or 8 or 10]"));
+				break;
+			}
 			break;
 		case 43:
 			if (optlen == 6)
@@ -640,7 +679,7 @@
 			else if (optlen == 4)
 				ND_PRINT((ndo, " %u", EXTRACT_16BITS(option + 2)));
 			else
-				ND_PRINT((ndo, " optlen != 4 or 6"));
+				ND_PRINT((ndo, " [optlen != 4 or 6]"));
 			break;
 		case 44:
 			if (optlen > 2) {
```
