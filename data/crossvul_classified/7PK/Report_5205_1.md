# CrossVul Fix Pair: 7PK in c
**Pair ID:** 5205_1
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5205_1`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```c
Lines 421-461 of the vulnerable file.


					if (zrtpChannelContext->peerPackets[COMMIT_MESSAGE_STORE_ID] == NULL) {
						free (messageData);
						/* we have no Commit message in this channel, this DHPart2 shall never have arrived, discard it as invalid */
						return BZRTP_PARSER_ERROR_UNEXPECTEDMESSAGE;
					}
					peerCommitMessageData = (bzrtpCommitMessage_t *)zrtpChannelContext->peerPackets[COMMIT_MESSAGE_STORE_ID]->messageData;
					/* Check H2 = SHA256(H1) */
					bctoolbox_sha256(messageData->H1, 32, 32, checkH2);
					if (memcmp(checkH2, peerCommitMessageData->H2, 32) != 0) {
						free (messageData);
						return BZRTP_PARSER_ERROR_UNMATCHINGHASHCHAIN;
					}
					/* Check the Commit MAC message. 
					 * MAC is 8 bytes long and is computed on the message(skip the ZRTP_PACKET_HEADER) and exclude the mac itself (-8 bytes from message Length) */
					bctoolbox_hmacSha256(messageData->H1, 32, zrtpChannelContext->peerPackets[COMMIT_MESSAGE_STORE_ID]->packetString+ZRTP_PACKET_HEADER_LENGTH, zrtpChannelContext->peerPackets[COMMIT_MESSAGE_STORE_ID]->messageLength-8, 8, checkMAC);
					if (memcmp(checkMAC, peerCommitMessageData->MAC, 8) != 0) {
						free (messageData);
						return BZRTP_PARSER_ERROR_UNMATCHINGMAC;
					}
				} else { /* if we are initiator(we didn't received any commit message and then no H2), we must check that H3=SHA256(SHA256(H1)) and the Hello message MAC */
					uint8_t checkH2[32];
					uint8_t checkH3[32];
					uint8_t checkMAC[32];
					bzrtpHelloMessage_t *peerHelloMessageData;

					if (zrtpChannelContext->peerPackets[HELLO_MESSAGE_STORE_ID] == NULL) {
						free (messageData);
						/* we have no Hello message in this channel, this DHPart1 shall never have arrived, discard it as invalid */
						return BZRTP_PARSER_ERROR_UNEXPECTEDMESSAGE;
					}
					peerHelloMessageData = (bzrtpHelloMessage_t *)zrtpChannelContext->peerPackets[HELLO_MESSAGE_STORE_ID]->messageData;
					/* Check H3 = SHA256(SHA256(H1)) */
					bctoolbox_sha256(messageData->H1, 32, 32, checkH2);
					bctoolbox_sha256(checkH2, 32, 32, checkH3);
					if (memcmp(checkH3, peerHelloMessageData->H3, 32) != 0) {
						free (messageData);
						return BZRTP_PARSER_ERROR_UNMATCHINGHASHCHAIN;
					}
					/* Check the hello MAC message. 
					 * MAC is 8 bytes long and is computed on the message(skip the ZRTP_PACKET_HEADER) and exclude the mac itself (-8 bytes from message Length) */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -438,6 +438,32 @@
 						free (messageData);
 						return BZRTP_PARSER_ERROR_UNMATCHINGMAC;
 					}
+
+					/* Check the hvi received in the commit message  - RFC section 4.4.1.1*/
+					/* First compute the expected hvi */
+					/* hvi = hash(initiator's DHPart2 message(current zrtpPacket)) || responder's Hello message) using the agreed hash function truncated to 256 bits */
+					/* create a string with the messages concatenated */
+					{
+						uint8_t computedHvi[32];
+						uint16_t HelloMessageLength = zrtpChannelContext->selfPackets[HELLO_MESSAGE_STORE_ID]->messageLength;
+						uint16_t DHPartHelloMessageStringLength = zrtpPacket->messageLength + HelloMessageLength;
+
+						uint8_t *DHPartHelloMessageString = (uint8_t *)malloc(DHPartHelloMessageStringLength*sizeof(uint8_t));
+
+						memcpy(DHPartHelloMessageString, input+ZRTP_PACKET_HEADER_LENGTH, zrtpPacket->messageLength);
+						memcpy(DHPartHelloMessageString+zrtpPacket->messageLength, zrtpChannelContext->selfPackets[HELLO_MESSAGE_STORE_ID]->packetString+ZRTP_PACKET_HEADER_LENGTH, HelloMessageLength);
+
+						zrtpChannelContext->hashFunction(DHPartHelloMessageString, DHPartHelloMessageStringLength, 32, computedHvi);
+
+						free(DHPartHelloMessageString);
+
+						/* Compare computed and received hvi */
+						if (memcmp(computedHvi, peerCommitMessageData->hvi, 32)!=0) {
+							free (messageData);
+							return BZRTP_PARSER_ERROR_UNMATCHINGHVI;
+						}
+					}
+
 				} else { /* if we are initiator(we didn't received any commit message and then no H2), we must check that H3=SHA256(SHA256(H1)) and the Hello message MAC */
 					uint8_t checkH2[32];
 					uint8_t checkH3[32];
@@ -482,7 +508,7 @@
 				/* attach the message structure to the packet one */
 				zrtpPacket->messageData = (void *)messageData;
 
-				/* the parsed commit packet must be saved as it is used to generate the total_hash */
+				/* the parsed packet must be saved as it is used to generate the total_hash */
 				zrtpPacket->packetString = (uint8_t *)malloc(inputLength*sizeof(uint8_t));
 				memcpy(zrtpPacket->packetString, input, inputLength); /* store the whole packet even if we may use the message only */
 			}
```
