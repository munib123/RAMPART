# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 600_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `600_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 970-1010 of the vulnerable file.

    } else {
      curAuthenticatorBlock_.clear();
    }
  }
  return ErrorCode::NO_ERROR;
}

ErrorCode HTTP2Codec::checkNewStream(uint32_t streamId, bool trailersAllowed) {
  if (streamId == 0) {
    goawayErrorMessage_ = folly::to<string>(
        "GOAWAY error: received streamID=", streamId,
        " as invalid new stream for lastStreamID_=", lastStreamID_);
    VLOG(4) << goawayErrorMessage_;
    return ErrorCode::PROTOCOL_ERROR;
  }
  parsingDownstreamTrailers_ = trailersAllowed && (streamId <= lastStreamID_);
  if (parsingDownstreamTrailers_) {
    VLOG(4) << "Parsing downstream trailers streamId=" << streamId;
  }

  if (sessionClosing_ != ClosingState::CLOSED) {
    lastStreamID_ = streamId;
  }

  if (isInitiatedStream(streamId)) {
    // this stream should be initiated by us, not by peer
    goawayErrorMessage_ = folly::to<string>(
        "GOAWAY error: invalid new stream received with streamID=", streamId);
    VLOG(4) << goawayErrorMessage_;
    return ErrorCode::PROTOCOL_ERROR;
  } else {
    return ErrorCode::NO_ERROR;
  }
}

size_t HTTP2Codec::generateConnectionPreface(folly::IOBufQueue& writeBuf) {
  if (transportDirection_ == TransportDirection::UPSTREAM) {
    VLOG(4) << "generating connection preface";
    writeBuf.append(http2::kConnectionPreface);
    return http2::kConnectionPreface.length();
  }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -987,7 +987,7 @@
     VLOG(4) << "Parsing downstream trailers streamId=" << streamId;
   }
 
-  if (sessionClosing_ != ClosingState::CLOSED) {
+  if (sessionClosing_ != ClosingState::CLOSED && streamId > lastStreamID_) {
     lastStreamID_ = streamId;
   }
 
@@ -1313,6 +1313,7 @@
 size_t HTTP2Codec::generateTrailers(folly::IOBufQueue& writeBuf,
                                     StreamID stream,
                                     const HTTPHeaders& trailers) {
+  VLOG(4) << "generating TRAILERS for stream=" << stream;
   std::vector<compress::Header> allHeaders;
   CodecUtil::appendHeaders(trailers, allHeaders, HTTP_HEADER_NONE);
 
```
