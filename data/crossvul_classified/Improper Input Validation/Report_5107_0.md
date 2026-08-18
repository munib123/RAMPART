# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5107_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5107_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 4081-4122 of the vulnerable file.

                                macinf->content[j+chan] = lchId_type_table[1];    /*Base MAC content on logical channel id (Table is in packet-nbap.h)*/
                                rlcinf->mode[j+chan] = lchId_rlc_map[1];    /*Based RLC mode on logical channel id*/

                            }
                            /*Indicate we don't have multiplexing.*/
                            else if (p_conv_data->dchs_in_flow_list[chan] == 24 && tb_size != 340) {
                                macinf->ctmux[j+chan] = FALSE;/*Set TRUE if this channel is multiplexed (ie. C/T flag exists)*/

                                /*g_warning("settin this for %d", pinfo->num);*/
                                macinf->lchid[j+chan] = fake_lchid;
                                macinf->fake_chid[j+chan] = TRUE;
                                macinf->content[j+chan] = MAC_CONTENT_PS_DTCH; /*lchId_type_table[fake_lchid];*/    /*Base MAC content on logical channel id (Table is in packet-nbap.h)*/
                                rlcinf->mode[j+chan] = RLC_AM;/*lchId_rlc_map[fake_lchid];*/    /*Based RLC mode on logical channel id*/
                            }
                            /*We have multiplexing*/
                            else {
                                macinf->ctmux[j+chan] = TRUE;/*Set TRUE if this channel is multiplexed (ie. C/T flag exists)*/

                                /* Peek at C/T, different RLC params for different logical channels */
                                /*C/T is 4 bits according to 3GPP TS 25.321, paragraph 9.2.1, from MAC header (not FP)*/
                                c_t = tvb_get_bits8(tvb, tb_bit_off/*(2+p_conv_data->num_dch_in_flow)*8*/, 4);    /* c_t = tvb_get_guint8(tvb, offset);*/
                                macinf->lchid[j+chan] = c_t+1;

                                macinf->content[j+chan] = lchId_type_table[c_t+1];    /*Base MAC content on logical channel id (Table is in packet-nbap.h)*/
                                rlcinf->mode[j+chan] = lchId_rlc_map[c_t+1];    /*Based RLC mode on logical channel id*/
                            }
                        } else {
                            fake_lchid = make_fake_lchid(pinfo, p_conv_data->dchs_in_flow_list[chan]);
                            macinf->ctmux[j+chan] = FALSE;/*Set TRUE if this channel is multiplexed (ie. C/T flag exists)*/
                            /*macinf->content[j+chan] = MAC_CONTENT_CS_DTCH;*/
                            macinf->content[j+chan] = lchId_type_table[fake_lchid];


                            rlcinf->mode[j+chan] = lchId_rlc_map[fake_lchid];

                            /*Generate virtual logical channel id*/
                            /************************/
                            /*TODO: Once proper lchid is always set, this has to be removed*/
                            macinf->fake_chid[j+chan] = TRUE;
                            macinf->lchid[j+chan] = fake_lchid;  /*make_fake_lchid(pinfo, p_conv_data->dchs_in_flow_list[chan]);*/
                            /************************/
                        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -4098,11 +4098,11 @@
 
                                 /* Peek at C/T, different RLC params for different logical channels */
                                 /*C/T is 4 bits according to 3GPP TS 25.321, paragraph 9.2.1, from MAC header (not FP)*/
-                                c_t = tvb_get_bits8(tvb, tb_bit_off/*(2+p_conv_data->num_dch_in_flow)*8*/, 4);    /* c_t = tvb_get_guint8(tvb, offset);*/
-                                macinf->lchid[j+chan] = c_t+1;
-
-                                macinf->content[j+chan] = lchId_type_table[c_t+1];    /*Base MAC content on logical channel id (Table is in packet-nbap.h)*/
-                                rlcinf->mode[j+chan] = lchId_rlc_map[c_t+1];    /*Based RLC mode on logical channel id*/
+                                c_t = (tvb_get_bits8(tvb, tb_bit_off/*(2+p_conv_data->num_dch_in_flow)*8*/, 4) + 1) % 0xf;    /* c_t = tvb_get_guint8(tvb, offset);*/
+                                macinf->lchid[j+chan] = c_t;
+
+                                macinf->content[j+chan] = lchId_type_table[c_t];    /*Base MAC content on logical channel id (Table is in packet-nbap.h)*/
+                                rlcinf->mode[j+chan] = lchId_rlc_map[c_t];    /*Based RLC mode on logical channel id*/
                             }
                         } else {
                             fake_lchid = make_fake_lchid(pinfo, p_conv_data->dchs_in_flow_list[chan]);
```
