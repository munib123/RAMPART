# CrossVul Fix Pair: Data Processing Errors in c
**Pair ID:** 1379_0
**Vulnerability Class:** Data Processing Errors
**CWE:** CWE-19
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1379_0`)

## Vulnerability Information & PoC

## Description
Data Processing Errors

## Vulnerable Code
```c
Lines 69-109 of the vulnerable file.

    folly::exception_wrapper) {
  // Null implementation to terminate the call in this handler
}

template <typename Pipeline, typename R>
void AcceptRoutingHandler<Pipeline, R>::onRoutingData(
    uint64_t connId,
    typename RoutingDataHandler<R>::RoutingData& routingData) {
  // Get the routing pipeline corresponding to this connection
  auto routingPipelineIter = routingPipelines_.find(connId);
  if (routingPipelineIter == routingPipelines_.end()) {
    VLOG(2) << "Connection has already been closed, "
               "or routed to a worker thread.";
    return;
  }
  auto routingPipeline = std::move(routingPipelineIter->second);
  routingPipelines_.erase(routingPipelineIter);

  // Fetch the socket from the pipeline and pause reading from the
  // socket
  auto socket = std::dynamic_pointer_cast<folly::AsyncSocket>(
      routingPipeline->getTransport());
  routingPipeline->transportInactive();
  socket->detachEventBase();

  // Hash based on routing data to pick a new acceptor
  uint64_t hash = std::hash<R>()(routingData.routingData);
  auto acceptor = acceptors_[hash % acceptors_.size()];

  // Switch to the new acceptor's thread
  acceptor->getEventBase()->runInEventBaseThread(
      [ =, routingData = std::move(routingData) ]() mutable {
        socket->attachEventBase(acceptor->getEventBase());

        auto routingHandler =
            routingPipeline->template getHandler<RoutingDataHandler<R>>();
        DCHECK(routingHandler);
        auto transportInfo = routingPipeline->getTransportInfo();
        auto pipeline = childPipelineFactory_->newPipeline(
            socket, routingData.routingData, routingHandler, transportInfo);

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -86,8 +86,9 @@
 
   // Fetch the socket from the pipeline and pause reading from the
   // socket
-  auto socket = std::dynamic_pointer_cast<folly::AsyncSocket>(
+  auto socket = std::dynamic_pointer_cast<folly::AsyncTransportWrapper>(
       routingPipeline->getTransport());
+  CHECK(socket);
   routingPipeline->transportInactive();
   socket->detachEventBase();
 
```
