# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 1657_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1657_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 920-965 of the vulnerable file.

     337,   338,   339,   340,   341,   342,   343,   344,   345,   353,
     359,   368,   369,   370,   371,   372,   376,   377,   378,   382,
     386,   387,   391,   392,   393,   394,   395,   396,   397,   398,
     399,   400,   401,   402,   403,   404,   405,   414,   422,   423,
     433,   435,   437,   448,   450,   452,   457,   459,   461,   463,
     465,   467,   472,   474,   478,   485,   495,   497,   499,   501,
     503,   505,   507,   524,   529,   530,   534,   536,   538,   540,
     542,   544,   546,   548,   550,   552,   554,   564,   566,   575,
     583,   584,   588,   589,   590,   591,   592,   593,   594,   595,
     599,   606,   616,   626,   635,   644,   653,   654,   658,   659,
     660,   661,   662,   663,   664,   673,   677,   681,   686,   691,
     696,   709,   722,   734,   735,   740,   741,   742,   743,   744,
     745,   746,   747,   748,   749,   750,   751,   752,   753,   757,
     759,   764,   765,   766,   770,   772,   777,   778,   779,   780,
     781,   782,   783,   784,   792,   797,   799,   804,   805,   806,
     807,   808,   809,   810,   811,   819,   821,   826,   833,   843,
     844,   845,   846,   847,   848,   849,   865,   869,   870,   874,
     875,   876,   877,   878,   879,   880,   889,   890,   906,   912,
     914,   916,   918,   920,   923,   925,   936,   938,   940,   950,
     952,   954,   956,   958,   963,   965,   969,   973,   975,   980,
     982,   986,   987,   991,   992,   996,  1011,  1016,  1024,  1025,
    1029,  1030,  1031,  1032,  1036,  1037,  1038,  1048,  1049,  1053,
    1055,  1060,  1062,  1066,  1071,  1072,  1076,  1077,  1081,  1090,
    1091,  1095,  1096,  1105,  1120,  1124,  1125,  1129,  1130,  1134,
    1135,  1139,  1144,  1148,  1152,  1153,  1157,  1162,  1163,  1167,
    1169,  1171,  1173,  1175
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "T_Age", "T_All", "T_Allan", "T_Auth",
  "T_Autokey", "T_Automax", "T_Average", "T_Bclient", "T_Beacon", "T_Bias",
  "T_Broadcast", "T_Broadcastclient", "T_Broadcastdelay", "T_Burst",
  "T_Calibrate", "T_Calldelay", "T_Ceiling", "T_Clockstats", "T_Cohort",
  "T_ControlKey", "T_Crypto", "T_Cryptostats", "T_Day", "T_Default",
  "T_Digest", "T_Disable", "T_Discard", "T_Dispersion", "T_Double",
  "T_Driftfile", "T_Drop", "T_Ellipsis", "T_Enable", "T_End", "T_False",
  "T_File", "T_Filegen", "T_Flag1", "T_Flag2", "T_Flag3", "T_Flag4",
  "T_Flake", "T_Floor", "T_Freq", "T_Fudge", "T_Host", "T_Huffpuff",
  "T_Iburst", "T_Ident", "T_Ignore", "T_Incalloc", "T_Incmem",
  "T_Initalloc", "T_Initmem", "T_Includefile", "T_Integer", "T_Interface",
  "T_Ipv4", "T_Ipv4_flag", "T_Ipv6", "T_Ipv6_flag", "T_Kernel", "T_Key",
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -937,12 +937,12 @@
      875,   876,   877,   878,   879,   880,   889,   890,   906,   912,
      914,   916,   918,   920,   923,   925,   936,   938,   940,   950,
      952,   954,   956,   958,   963,   965,   969,   973,   975,   980,
-     982,   986,   987,   991,   992,   996,  1011,  1016,  1024,  1025,
-    1029,  1030,  1031,  1032,  1036,  1037,  1038,  1048,  1049,  1053,
-    1055,  1060,  1062,  1066,  1071,  1072,  1076,  1077,  1081,  1090,
-    1091,  1095,  1096,  1105,  1120,  1124,  1125,  1129,  1130,  1134,
-    1135,  1139,  1144,  1148,  1152,  1153,  1157,  1162,  1163,  1167,
-    1169,  1171,  1173,  1175
+     982,   986,   987,   991,   992,   996,  1021,  1026,  1034,  1035,
+    1039,  1040,  1041,  1042,  1046,  1047,  1048,  1058,  1059,  1063,
+    1065,  1070,  1072,  1076,  1081,  1082,  1086,  1087,  1091,  1100,
+    1101,  1105,  1106,  1115,  1130,  1134,  1135,  1139,  1140,  1144,
+    1145,  1149,  1154,  1158,  1162,  1163,  1167,  1172,  1173,  1177,
+    1179,  1181,  1183,  1185
 };
 #endif
 
@@ -3532,14 +3532,24 @@
 /* Line 1455 of yacc.c  */
 #line 997 "ntp_parser.y"
     {
-			char prefix = (yyvsp[(1) - (1)].String)[0];
-			char *type = (yyvsp[(1) - (1)].String) + 1;
+			char	prefix;
+			char *	type;
 			
-			if (prefix != '+' && prefix != '-' && prefix != '=') {
-				yyerror("Logconfig prefix is not '+', '-' or '='\n");
-			}
-			else
-				(yyval.Attr_val) = create_attr_sval(prefix, estrdup(type));
+			switch ((yyvsp[(1) - (1)].String)[0]) {
+			
+			case '+':
+			case '-':
+			case '=':
+				prefix = (yyvsp[(1) - (1)].String)[0];
+				type = (yyvsp[(1) - (1)].String) + 1;
+				break;
+				
+			default:
+				prefix = '=';
+				type = (yyvsp[(1) - (1)].String);
+			}	
+			
+			(yyval.Attr_val) = create_attr_sval(prefix, estrdup(type));
 			YYFREE((yyvsp[(1) - (1)].String));
 		}
     break;
@@ -3547,7 +3557,7 @@
   case 216:
 
 /* Line 1455 of yacc.c  */
-#line 1012 "ntp_parser.y"
+#line 1022 "ntp_parser.y"
     {
 			enqueue(cfgt.nic_rules,
 				create_nic_rule_node((yyvsp[(3) - (3)].Integer), NULL, (yyvsp[(2) - (3)].Integer)));
@@ -3557,7 +3567,7 @@
   case 217:
 
 /* Line 1455 of yacc.c  */
-#line 1017 "ntp_parser.y"
+#line 1027 "ntp_parser.y"
     {
 			enqueue(cfgt.nic_rules,
 				create_nic_rule_node(0, (yyvsp[(3) - (3)].String), (yyvsp[(2) - (3)].Integer)));
@@ -3567,77 +3577,77 @@
   case 227:
 
 /* Line 1455 of yacc.c  */
-#line 1048 "ntp_parser.y"
+#line 1058 "ntp_parser.y"
     { (yyval.Queue) = enqueue((yyvsp[(1) - (2)].Queue), create_ival((yyvsp[(2) - (2)].Integer))); }
     break;
 
   case 228:
 
 /* Line 1455 of yacc.c  */
-#line 1049 "ntp_parser.y"
+#line 1059 "ntp_parser.y"
     { (yyval.Queue) = enqueue_in_new_queue(create_ival((yyvsp[(1) - (1)].Integer))); }
     break;
 
   case 229:
 
 /* Line 1455 of yacc.c  */
-#line 1054 "ntp_parser.y"
+#line 1064 "ntp_parser.y"
     { (yyval.Queue) = enqueue((yyvsp[(1) - (2)].Queue), (yyvsp[(2) - (2)].Attr_val)); }
     break;
 
   case 230:
 
 /* Line 1455 of yacc.c  */
-#line 1056 "ntp_parser.y"
+#line 1066 "ntp_parser.y"
     { (yyval.Queue) = enqueue_in_new_queue((yyvsp[(1) - (1)].Attr_val)); }
     break;
 
   case 231:
 
 /* Line 1455 of yacc.c  */
-#line 1061 "ntp_parser.y"
+#line 1071 "ntp_parser.y"
     { (yyval.Attr_val) = create_attr_ival('i', (yyvsp[(1) - (1)].Integer)); }
     break;
 
   case 233:
 
 /* Line 1455 of yacc.c  */
-#line 1067 "ntp_parser.y"
+#line 1077 "ntp_parser.y"
     { (yyval.Attr_val) = create_attr_shorts('-', (yyvsp[(2) - (5)].Integer), (yyvsp[(4) - (5)].Integer)); }
     break;
 
   case 234:
 
 /* Line 1455 of yacc.c  */
-#line 1071 "ntp_parser.y"
+#line 1081 "ntp_parser.y"
     { (yyval.Queue) = enqueue((yyvsp[(1) - (2)].Queue), create_pval((yyvsp[(2) - (2)].String))); }
     break;
 
   case 235:
 
 /* Line 1455 of yacc.c  */
-#line 1072 "ntp_parser.y"
+#line 1082 "ntp_parser.y"
     { (yyval.Queue) = enqueue_in_new_queue(create_pval((yyvsp[(1) - (1)].String))); }
     break;
 
   case 236:
 
 /* Line 1455 of yacc.c  */
-#line 1076 "ntp_parser.y"
+#line 1086 "ntp_parser.y"
     { (yyval.Queue) = enqueue((yyvsp[(1) - (2)].Queue), (yyvsp[(2) - (2)].Address_node)); }
     break;
 
   case 237:
 
 /* Line 1455 of yacc.c  */
-#line 1077 "ntp_parser.y"
+#line 1087 "ntp_parser.y"
     { (yyval.Queue) = enqueue_in_new_queue((yyvsp[(1) - (1)].Address_node)); }
     break;
 
   case 238:
 
 /* Line 1455 of yacc.c  */
-#line 1082 "ntp_parser.y"
+#line 1092 "ntp_parser.y"
     {
 			if ((yyvsp[(1) - (1)].Integer) != 0 && (yyvsp[(1) - (1)].Integer) != 1) {
 				yyerror("Integer value is not boolean (0 or 1). Assuming 1");
@@ -3651,28 +3661,28 @@
   case 239:
 
 /* Line 1455 of yacc.c  */
-#line 1090 "ntp_parser.y"
+#line 1100 "ntp_parser.y"
     { (yyval.Integer) = 1; }
     break;
 
   case 240:
 
 /* Line 1455 of yacc.c  */
-#line 1091 "ntp_parser.y"
+#line 1101 "ntp_parser.y"
     { (yyval.Integer) = 0; }
     break;
 
   case 241:
 
 /* Line 1455 of yacc.c  */
-#line 1095 "ntp_parser.y"
+#line 1105 "ntp_parser.y"
     { (yyval.Double) = (double)(yyvsp[(1) - (1)].Integer); }
     break;
 
   case 243:
 
 /* Line 1455 of yacc.c  */
-#line 1106 "ntp_parser.y"
+#line 1116 "ntp_parser.y"
     {
 			cfgt.sim_details = create_sim_node((yyvsp[(3) - (5)].Queue), (yyvsp[(4) - (5)].Queue));
 
@@ -3684,147 +3694,147 @@
   case 244:
 
 /* Line 1455 of yacc.c  */
-#line 1120 "ntp_parser.y"
+#line 1130 "ntp_parser.y"
     { old_config_style = 0; }
     break;
 
   case 245:
 
 /* Line 1455 of yacc.c  */
-#line 1124 "ntp_parser.y"
+#line 1134 "ntp_parser.y"
     { (yyval.Queue) = enqueue((yyvsp[(1) - (3)].Queue), (yyvsp[(2) - (3)].Attr_val)); }
     break;
 
   case 246:
 
 /* Line 1455 of yacc.c  */
-#line 1125 "ntp_parser.y"
+#line 1135 "ntp_parser.y"
     { (yyval.Queue) = enqueue_in_new_queue((yyvsp[(1) - (2)].Attr_val)); }
     break;
 
   case 247:
 
 /* Line 1455 of yacc.c  */
-#line 1129 "ntp_parser.y"
+#line 1139 "ntp_parser.y"
     { (yyval.Attr_val) = create_attr_dval((yyvsp[(1) - (3)].Integer), (yyvsp[(3) - (3)].Double)); }
     break;
 
   case 248:
 
 /* Line 1455 of yacc.c  */
-#line 1130 "ntp_parser.y"
+#line 1140 "ntp_parser.y"
     { (yyval.Attr_val) = create_attr_dval((yyvsp[(1) - (3)].Integer), (yyvsp[(3) - (3)].Double)); }
     break;
 
   case 249:
 
 /* Line 1455 of yacc.c  */
-#line 1134 "ntp_parser.y"
+#line 1144 "ntp_parser.y"
     { (yyval.Queue) = enqueue((yyvsp[(1) - (2)].Queue), (yyvsp[(2) - (2)].Sim_server)); }
     break;
 
   case 250:
 
 /* Line 1455 of yacc.c  */
-#line 1135 "ntp_parser.y"
+#line 1145 "ntp_parser.y"
     { (yyval.Queue) = enqueue_in_new_queue((yyvsp[(1) - (1)].Sim_server)); }
     break;
 
   case 251:
 
 /* Line 1455 of yacc.c  */
-#line 1140 "ntp_parser.y"
+#line 1150 "ntp_parser.y"
     { (yyval.Sim_server) = create_sim_server((yyvsp[(1) - (5)].Address_node), (yyvsp[(3) - (5)].Double), (yyvsp[(4) - (5)].Queue)); }
     break;
 
   case 252:
 
 /* Line 1455 of yacc.c  */
-#line 1144 "ntp_parser.y"
+#line 1154 "ntp_parser.y"
     { (yyval.Double) = (yyvsp[(3) - (4)].Double); }
     break;
 
   case 253:
 
 /* Line 1455 of yacc.c  */
-#line 1148 "ntp_parser.y"
+#line 1158 "ntp_parser.y"
     { (yyval.Address_node) = (yyvsp[(3) - (3)].Address_node); }
     break;
 
   case 254:
 
 /* Line 1455 of yacc.c  */
-#line 1152 "ntp_parser.y"
+#line 1162 "ntp_parser.y"
     { (yyval.Queue) = enqueue((yyvsp[(1) - (2)].Queue), (yyvsp[(2) - (2)].Sim_script)); }
     break;
 
   case 255:
 
 /* Line 1455 of yacc.c  */
-#line 1153 "ntp_parser.y"
+#line 1163 "ntp_parser.y"
     { (yyval.Queue) = enqueue_in_new_queue((yyvsp[(1) - (1)].Sim_script)); }
     break;
 
   case 256:
 
 /* Line 1455 of yacc.c  */
-#line 1158 "ntp_parser.y"
+#line 1168 "ntp_parser.y"
     { (yyval.Sim_script) = create_sim_script_info((yyvsp[(3) - (6)].Double), (yyvsp[(5) - (6)].Queue)); }
     break;
 
   case 257:
 
 /* Line 1455 of yacc.c  */
-#line 1162 "ntp_parser.y"
... (diff truncated)
```
