# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4950_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4950_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 141-181 of the vulnerable file.

 * SIP_MSG:
 * the SIP message as it has been received.
 *
 * The length of the structure, will be ((short*)payload)[1] + ((short*)payload)[2]
 *
 * TODO: msg->parsed_uri msg->parsed_orig_uri_ok, msg->first_line->u.request.uri
 * buggy and little bit fuzzy
 */
int encode_msg(struct sip_msg *msg,char *payload,int len)
{
   int i,j,k,u,request;
   unsigned short int h;
   struct hdr_field* hf;
   struct msg_start* ms;
   struct sip_uri miuri;
   char *myerror=NULL;
   ptrdiff_t diff;

   if(len < MAX_ENCODED_MSG + MAX_MESSAGE_LEN)
      return -1;
   if(parse_headers(msg,HDR_EOH_F,0)<0){
      myerror="in parse_headers";
      goto error;
   }
   memset(payload,0,len);
   ms=&msg->first_line;
	if(ms->type == SIP_REQUEST)
		request=1;
	else if(ms->type == SIP_REPLY)
		request=0;
	else{
		myerror="message is neither request nor response";
		goto error;
	}
	if(request) {
		for(h=0;h<32;j=(0x01<<h),h++)
			if(j & ms->u.request.method_value)
				break;
	} else {
		h=(unsigned short)(ms->u.reply.statuscode);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -158,6 +158,7 @@
 
    if(len < MAX_ENCODED_MSG + MAX_MESSAGE_LEN)
       return -1;
+
    if(parse_headers(msg,HDR_EOH_F,0)<0){
       myerror="in parse_headers";
       goto error;
@@ -266,6 +267,11 @@
    /*j+=k;*/
    /*pkg_free(payload2);*/
    /*now we copy the actual message after the headers-meta-section*/
+
+	if(len < j + msg->len + 1) {
+   	   LM_ERR("not enough space to encode sip message\n");
+   	   return -1;
+	}
    memcpy(&payload[j],msg->buf,msg->len);
    LM_DBG("msglen = %d,msg starts at %d\n",msg->len,j);
    j=htons(j);
```
