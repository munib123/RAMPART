# CrossVul Fix Pair: Reliance on Reverse DNS Resolution for a Security-Critical Action in go
**Pair ID:** 3948_0
**Vulnerability Class:** Reliance on Reverse DNS Resolution for a Security-Critical Action
**CWE:** CWE-350
**Language:** go
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3948_0`)

## Vulnerability Information & PoC

## Description
Reliance on Reverse DNS Resolution for a Security-Critical Action - Since DNS names can be easily spoofed or misreported, and it may be difficult for the product to detect if a trusted DNS server has been compromised, DNS names do not constitute a valid authenticat...

## Vulnerable Code
```go
Lines 46-89 of the vulnerable file.


                 /-------\
(container-veth)-+ weave +
                 \-------/

"weave" is an Open vSwitch datapath, and capture/injection are as in
BridgedFastdp. Not used by default due to missing conntrack support in
datapath of old kernel versions (https://github.com/weaveworks/weave/issues/1577).
*/

const (
	WeaveBridgeName  = "weave"
	DatapathName     = "datapath"
	DatapathIfName   = "vethwe-datapath"
	BridgeIfName     = "vethwe-bridge"
	PcapIfName       = "vethwe-pcap"
	NoMasqLocalIpset = ipset.Name("weaver-no-masq-local")
)

type Bridge interface {
	init(config *BridgeConfig) error // create and initialise bridge device(s)
	attach(veth *netlink.Veth) error // attach veth to bridge
	IsFastdp() bool                  // does this bridge use fastdp?
	String() string                  // human-readable type string
}

// Used to indicate a fallback to the Bridge type
var errBridgeNotSupported = errors.New("bridge not supported")

type bridgeImpl struct{ bridge netlink.Link }
type fastdpImpl struct{ datapathName string }
type bridgedFastdpImpl struct {
	bridgeImpl
	fastdpImpl
}

// Returns a string that is consistent with the weave script
func (bridgeImpl) String() string        { return "bridge" }
func (fastdpImpl) String() string        { return "fastdp" }
func (bridgedFastdpImpl) String() string { return "bridged_fastdp" }

// Used to decide whether to manage ODP tunnels
func (bridgeImpl) IsFastdp() bool        { return false }
func (fastdpImpl) IsFastdp() bool        { return true }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -63,10 +63,10 @@
 )
 
 type Bridge interface {
-	init(config *BridgeConfig) error // create and initialise bridge device(s)
-	attach(veth *netlink.Veth) error // attach veth to bridge
-	IsFastdp() bool                  // does this bridge use fastdp?
-	String() string                  // human-readable type string
+	init(procPath string, config *BridgeConfig) error // create and initialise bridge device(s)
+	attach(veth *netlink.Veth) error                  // attach veth to bridge
+	IsFastdp() bool                                   // does this bridge use fastdp?
+	String() string                                   // human-readable type string
 }
 
 // Used to indicate a fallback to the Bridge type
@@ -250,7 +250,7 @@
 	}
 
 	for {
-		if err := bridgeType.init(config); err != nil {
+		if err := bridgeType.init(procPath, config); err != nil {
 			if errors.Cause(err) == errBridgeNotSupported {
 				log.Warnf("Skipping bridge creation of %q due to: %s", bridgeType, err)
 				bridgeType = bridgeImpl{}
@@ -278,6 +278,10 @@
 		if err := sysctl(procPath, "net/ipv4/neigh/"+config.WeaveBridgeName+"/proxy_delay", "0"); err != nil {
 			return bridgeType, errors.Wrap(err, "setting proxy_arp")
 		}
+	}
+	// No ipv6 router advertisments please
+	if err := sysctl(procPath, "net/ipv6/conf/"+config.WeaveBridgeName+"/accept_ra", "0"); err != nil {
+		return bridgeType, errors.Wrap(err, "setting accept_ra to 0")
 	}
 
 	if err := linkSetUpByName(config.WeaveBridgeName); err != nil {
@@ -345,11 +349,11 @@
 	return nil
 }
 
-func (b bridgeImpl) init(config *BridgeConfig) error {
+func (b bridgeImpl) init(procPath string, config *BridgeConfig) error {
 	if err := b.initPrep(config); err != nil {
 		return err
 	}
-	if _, err := CreateAndAttachVeth(BridgeIfName, PcapIfName, config.WeaveBridgeName, config.MTU, true, false, func(veth netlink.Link) error {
+	if _, err := CreateAndAttachVeth(procPath, BridgeIfName, PcapIfName, config.WeaveBridgeName, config.MTU, true, false, func(veth netlink.Link) error {
 		return netlink.LinkSetUp(veth)
 	}); err != nil {
 		return errors.Wrap(err, "creating pcap veth pair")
@@ -361,7 +365,7 @@
 	return nil
 }
 
-func (f fastdpImpl) init(config *BridgeConfig) error {
+func (f fastdpImpl) init(procPath string, config *BridgeConfig) error {
 	odpSupported, err := odp.CreateDatapath(f.datapathName)
 	if !odpSupported {
 		msg := ""
@@ -392,14 +396,14 @@
 	return nil
 }
 
-func (bf bridgedFastdpImpl) init(config *BridgeConfig) error {
-	if err := bf.fastdpImpl.init(config); err != nil {
+func (bf bridgedFastdpImpl) init(procPath string, config *BridgeConfig) error {
+	if err := bf.fastdpImpl.init(procPath, config); err != nil {
 		return err
 	}
 	if err := bf.bridgeImpl.initPrep(config); err != nil {
 		return err
 	}
-	if _, err := CreateAndAttachVeth(BridgeIfName, DatapathIfName, config.WeaveBridgeName, config.MTU, true, false, func(veth netlink.Link) error {
+	if _, err := CreateAndAttachVeth(procPath, BridgeIfName, DatapathIfName, config.WeaveBridgeName, config.MTU, true, false, func(veth netlink.Link) error {
 		if err := netlink.LinkSetUp(veth); err != nil {
 			return errors.Wrapf(err, "setting link up on %q", veth.Attrs().Name)
 		}
```
