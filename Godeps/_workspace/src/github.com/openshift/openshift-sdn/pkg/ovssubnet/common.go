package ovssubnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"strings"
	"time"

	log "github.com/golang/glog"

	"github.com/openshift/openshift-sdn/pkg/netutils"
	"github.com/openshift/openshift-sdn/pkg/ovssubnet/api"
	"github.com/openshift/openshift-sdn/pkg/ovssubnet/controller/kube"
	"github.com/openshift/openshift-sdn/pkg/ovssubnet/controller/multitenant"
	"github.com/openshift/openshift-sdn/pkg/ovssubnet/controller/flannelsdn"

	"github.com/coreos/go-etcd/etcd"
)

const (
	// Maximum VXLAN Network Identifier as per RFC#7348
	MaxVNID = ((1 << 24) - 1)
)

type OvsController struct {
	subnetRegistry  api.SubnetRegistry
	localIP         string
	localSubnet     *api.Subnet
	hostName        string
	subnetAllocator *netutils.SubnetAllocator
	sig             chan struct{}
	ready           chan struct{}
	flowController  FlowController
	VNIDMap         map[string]uint
	netIDManager    *netutils.NetIDAllocator
	AdminNamespaces []string
	etcdClient      *etcd.Client
}

type FlowController interface {
	Setup(localSubnetCIDR, clusterNetworkCIDR, serviceNetworkCIDR string, mtu uint) error
	AddOFRules(nodeIP, nodeSubnetCIDR, localIP string) error
	DelOFRules(nodeIP, localIP string) error
	AddServiceOFRules(netID uint, IP string, protocol api.ServiceProtocol, port uint) error
	DelServiceOFRules(netID uint, IP string, protocol api.ServiceProtocol, port uint) error
}

func NewKubeController(sub api.SubnetRegistry, hostname string, selfIP string, ready chan struct{}) (*OvsController, error) {
	kubeController, err := NewController(sub, nil, hostname, selfIP, ready)
	if err == nil {
		kubeController.flowController = kube.NewFlowController()
	}
	return kubeController, err
}

func NewMultitenantController(sub api.SubnetRegistry, hostname string, selfIP string, ready chan struct{}) (*OvsController, error) {
	mtController, err := NewController(sub, nil, hostname, selfIP, ready)
	if err == nil {
		mtController.flowController = multitenant.NewFlowController()
	}
	return mtController, err
}

func NewFlannelSDNController(sub api.SubnetRegistry, etcdClient *etcd.Client, hostname string, selfIP string, ready chan struct{}) (*OvsController, error) {
	fsController, err := NewController(sub, etcdClient, hostname, selfIP, ready)
	if err == nil {
		fsController.flowController = flannelsdn.NewFlowController()
	}
	return fsController, err
}

func NewController(sub api.SubnetRegistry, etcdClient *etcd.Client, hostname string, selfIP string, ready chan struct{}) (*OvsController, error) {
	if selfIP == "" {
		var err error
		selfIP, err = GetNodeIP(hostname)
		if err != nil {
			return nil, err
		}
	}
	log.Infof("Self IP: %s.", selfIP)
	return &OvsController{
		subnetRegistry:  sub,
		localIP:         selfIP,
		hostName:        hostname,
		localSubnet:     nil,
		subnetAllocator: nil,
		VNIDMap:         make(map[string]uint),
		sig:             make(chan struct{}),
		ready:           ready,
		AdminNamespaces: make([]string, 0),
		etcdClient:      etcdClient,
	}, nil
}

func (oc *OvsController) StartMaster(sync bool, clusterNetworkCIDR string, clusterBitsPerSubnet uint, serviceNetworkCIDR string) error {
	// wait a minute for etcd to come alive
	status := oc.subnetRegistry.CheckEtcdIsAlive(60)
	if !status {
		log.Errorf("Etcd not running?")
		return errors.New("Etcd not reachable. Sync cluster check failed.")
	}

	nets, _, err := oc.subnetRegistry.GetNetNamespaces()
	if err != nil {
		return err
	}
	inUse := make([]uint, 0)
	for _, net := range nets {
		inUse = append(inUse, net.NetID)
		oc.VNIDMap[net.Name] = net.NetID
	}
	// VNID: 0 reserved for default namespace and can reach any network in the cluster
	// VNID: 1 to 9 are internally reserved for any special cases in the future
	oc.netIDManager, err = netutils.NewNetIDAllocator(10, MaxVNID, inUse)
	if err != nil {
		return err
	}

	result, err := oc.watchAndGetResource("Namespace")
	if err != nil {
		return err
	}
	namespaces := result.([]string)

	subrange := make([]string, 0)
	log.Errorf("######## namespaces %v", namespaces)
	// Get existing network allocations
	for _, nsName := range namespaces {
		net, err := getFlannelNetwork(oc.etcdClient, nsName)
		if net == nil || err != nil {
			log.Errorf("Unusable network '%s': %v", nsName, err)
			continue
		}

		subrange = append(subrange, net.Network)
	}

	oc.subnetAllocator, err = netutils.NewSubnetAllocator("10.0.0.0/8", 16, subrange)
	if err != nil {
		return err
	}

	// Handle existing namespaces without VNID
	for _, nsName := range namespaces {
		// Skip admin namespaces, they will have VNID: 0
		if oc.isAdminNamespace(nsName) {
			// Revoke VNID if already exists
			if _, ok := oc.VNIDMap[nsName]; ok {
				err := oc.revokeVNID(nsName)
				if err != nil {
					return err
				}
			}
			continue
		}
		// Skip if VNID already exists for the namespace
		if _, ok := oc.VNIDMap[nsName]; ok {
			continue
		}
		err := oc.assignVNID(nsName)
		if err != nil {
			return err
		}
	}

	return nil
}

func (oc *OvsController) isAdminNamespace(nsName string) bool {
	for _, name := range oc.AdminNamespaces {
		if name == nsName {
			return true
		}
	}
	return false
}

type FlannelNetwork struct {
	Network     string
	SubnetLen   uint
	SdnConfig   FlannelSdnConfig `json:"Backend"`
}

type FlannelSdnConfig struct {
	Type string
	VNI  uint
}

func getFlannelNetwork(etcdClient *etcd.Client, name string) (*FlannelNetwork, error) {
	key := path.Join("/coreos.com/network", name, "config")
	resp, err := etcdClient.Get(key, false, false)
	if err != nil {
		if e, ok := err.(*etcd.EtcdError); ok {
			if e.ErrorCode == 100 {
				return nil, nil
			}
		}
		return nil, err
	}

	n := new(FlannelNetwork)
	err = json.Unmarshal([]byte(resp.Node.Value), n)
	if err != nil {
		return nil, err
	}

	_, _, err = net.ParseCIDR(n.Network)
	if err != nil {
		return nil, err
	}
	if n.SdnConfig.Type != "ovs" {
		return nil, fmt.Errorf("Unexpected flannel network type '%s'", n.SdnConfig.Type)
	}

	return n, nil
}

func (oc *OvsController) updateFlannelNetwork(name string, vnid uint) error {
	found, err := getFlannelNetwork(oc.etcdClient, name)
	if err != nil {
		return err
	} else if found != nil {
		if found.SdnConfig.VNI != vnid {
			return fmt.Errorf("Network '%s' didn't match flannel network vnid %d (expected %d)", name, found.SdnConfig.VNI, vnid)
		}
		if found.SdnConfig.Type != "ovs" {
			return fmt.Errorf("Network '%s' already defined as backend type %s", name, found.SdnConfig.Type)
		}
	}

	sn, err := oc.subnetAllocator.GetNetwork()
	if err != nil {
		log.Errorf("Error creating subnet for network %s.", name)
		return err
	}

	var sdnConfig = FlannelSdnConfig{ "ovs", vnid }
	net := FlannelNetwork{
		Network:   sn.String(),
		SubnetLen: 24,
		SdnConfig: sdnConfig,
	}
	netMessage, err := json.Marshal(net)
	if err != nil {
		return err
	}

	key := path.Join("/coreos.com/network", name, "config")
	log.Infof("##### Adding flannel network %s key %s config '%s'", name, key, string(netMessage))
	_, err = oc.etcdClient.Set(key, string(netMessage), 0)
	if err != nil {
		return err
	}

	return nil
}

func (oc *OvsController) assignVNID(namespaceName string) error {
	_, err := oc.subnetRegistry.GetNetNamespace(namespaceName)
	if err != nil {
		netid, err := oc.netIDManager.GetNetID()
		if err != nil {
			return err
		}
		err = oc.subnetRegistry.WriteNetNamespace(namespaceName, netid)
		if err != nil {
			e := oc.netIDManager.ReleaseNetID(netid)
			if e != nil {
				log.Error("Error while releasing Net ID: %v", e)
			}
			return err
		}
		oc.VNIDMap[namespaceName] = netid

		err = oc.updateFlannelNetwork(namespaceName, netid)
		if err != nil {
			log.Error("Error adding flannel network for %s/%d: %v", namespaceName, netid, err)
		}
	}
	return nil
}

func (oc *OvsController) removeFlannelNetwork(name string) error {
	found, err := getFlannelNetwork(oc.etcdClient, name)
	if found != nil {
		_, ipnet, err := net.ParseCIDR(found.Network)
		if err == nil {
			oc.subnetAllocator.ReleaseNetwork(ipnet)
		}
	}

	key := path.Join("/coreos.com/network", name, "config")
	_, err = oc.etcdClient.Delete(key, false)
	if err != nil {
		return err
	}

	return nil
}

func (oc *OvsController) revokeVNID(namespaceName string) error {
	log.Infof("Revoking network %s.", namespaceName)

	err := oc.removeFlannelNetwork(namespaceName)
	if err != nil {
		log.Errorf("Failed to delete flannel network '%s': %v", namespaceName, err)
	}

	err = oc.subnetRegistry.DeleteNetNamespace(namespaceName)
	if err != nil {
		return err
	}
	netid, ok := oc.VNIDMap[namespaceName]
	if !ok {
		return fmt.Errorf("Error while fetching Net ID for namespace: %s", namespaceName)
	}
	err = oc.netIDManager.ReleaseNetID(netid)
	if err != nil {
		return fmt.Errorf("Error while releasing Net ID: %v", err)
	}
	delete(oc.VNIDMap, namespaceName)
	return nil
}

func (oc *OvsController) watchNetworks(ready chan<- bool, start <-chan string) {
	nsevent := make(chan *api.NamespaceEvent)
	stop := make(chan bool)
	go oc.subnetRegistry.WatchNamespaces(nsevent, ready, start, stop)
	for {
		select {
		case ev := <-nsevent:
			switch ev.Type {
			case api.Added:
				err := oc.assignVNID(ev.Name)
				if err != nil {
					log.Error("Error assigning Net ID: %v", err)
					continue
				}
			case api.Deleted:
				err := oc.revokeVNID(ev.Name)
				if err != nil {
					log.Error("Error revoking Net ID: %v", err)
					continue
				}
			}
		case <-oc.sig:
			log.Error("Signal received. Stopping watching of nodes.")
			stop <- true
			return
		}
	}
}

func (oc *OvsController) StartNode(sync, skipsetup bool, mtu uint) error {
	// call flow controller's setup
	err := oc.flowController.Setup("", "", "", 0)
	if err != nil {
		return err
	}

	result, err := oc.watchAndGetResource("NetNamespace")
	if err != nil {
		return err
	}
	nslist := result.([]api.NetNamespace)
	for _, ns := range nslist {
		oc.VNIDMap[ns.Name] = ns.NetID
	}

	result, err = oc.watchAndGetResource("Service")
	if err != nil {
		return err
	}
	services := result.([]api.Service)
	for _, svc := range services {
		oc.flowController.AddServiceOFRules(oc.VNIDMap[svc.Namespace], svc.IP, svc.Protocol, svc.Port)
	}

	if oc.ready != nil {
		close(oc.ready)
	}
	return nil
}

func (oc *OvsController) watchVnids(ready chan<- bool, start <-chan string) {
	stop := make(chan bool)
	netNsEvent := make(chan *api.NetNamespaceEvent)
	go oc.subnetRegistry.WatchNetNamespaces(netNsEvent, ready, start, stop)
	for {
		select {
		case ev := <-netNsEvent:
			switch ev.Type {
			case api.Added:
				oc.VNIDMap[ev.Name] = ev.NetID
			case api.Deleted:
				delete(oc.VNIDMap, ev.Name)
			}
		case <-oc.sig:
			log.Error("Signal received. Stopping watching of NetNamespaces.")
			stop <- true
			return
		}
	}
}

func (oc *OvsController) watchServices(ready chan<- bool, start <-chan string) {
	stop := make(chan bool)
	svcevent := make(chan *api.ServiceEvent)
	go oc.subnetRegistry.WatchServices(svcevent, ready, start, stop)
	for {
		select {
		case ev := <-svcevent:
			netid := oc.VNIDMap[ev.Service.Namespace]
			switch ev.Type {
			case api.Added:
				oc.flowController.AddServiceOFRules(netid, ev.Service.IP, ev.Service.Protocol, ev.Service.Port)
			case api.Deleted:
				oc.flowController.DelServiceOFRules(netid, ev.Service.IP, ev.Service.Protocol, ev.Service.Port)
			}
		case <-oc.sig:
			log.Error("Signal received. Stopping watching of services.")
			stop <- true
			return
		}
	}
}

func (oc *OvsController) Stop() {
	close(oc.sig)
}

func GetNodeIP(nodeName string) (string, error) {
	ip := net.ParseIP(nodeName)
	if ip == nil {
		addrs, err := net.LookupIP(nodeName)
		if err != nil {
			log.Errorf("Failed to lookup IP address for node %s: %v", nodeName, err)
			return "", err
		}
		for _, addr := range addrs {
			if addr.String() != "127.0.0.1" {
				ip = addr
				break
			}
		}
	}
	if ip == nil || len(ip.String()) == 0 {
		return "", fmt.Errorf("Failed to obtain IP address from node name: %s", nodeName)
	}
	return ip.String(), nil
}

// Wait for ready signal from Watch interface for the given resource
// Closes the ready channel as we don't need it anymore after this point
func waitForWatchReadiness(ready chan bool, resourceName string) {
	timeout := time.Minute
	select {
	case <-ready:
		close(ready)
	case <-time.After(timeout):
		log.Fatalf("Watch for resource %s is not ready(timeout: %v)", resourceName, timeout)
	}
	return
}

// watchAndGetResource will fetch current items in etcd and watch for any new
// changes for the given resource.
// Supported resources: nodes, subnets, namespaces, services and netnamespaces.
//
// To avoid any potential race conditions during this process, these steps are followed:
// 1. Initiator(master/node): Watch for a resource as an async op, lets say WatchProcess
// 2. WatchProcess: When ready for watching, send ready signal to initiator
// 3. Initiator: Wait for watch resource to be ready
//    This is needed as step-1 is an asynchronous operation
// 4. WatchProcess: Collect new changes in the queue but wait for initiator
//    to indicate which version to start from
// 5. Initiator: Get existing items with their latest version for the resource
// 6. Initiator: Send version from step-5 to WatchProcess
// 7. WatchProcess: Ignore any items with version <= start version got from initiator on step-6
// 8. WatchProcess: Handle new changes
func (oc *OvsController) watchAndGetResource(resourceName string) (interface{}, error) {
	ready := make(chan bool)
	start := make(chan string)

	var getOutput interface{}
	var version string
	var err error

	switch strings.ToLower(resourceName) {
	case "namespace":
		go oc.watchNetworks(ready, start)
		waitForWatchReadiness(ready, resourceName)
		getOutput, version, err = oc.subnetRegistry.GetNamespaces()
	case "netnamespace":
		go oc.watchVnids(ready, start)
		waitForWatchReadiness(ready, resourceName)
		getOutput, version, err = oc.subnetRegistry.GetNetNamespaces()
	case "service":
		go oc.watchServices(ready, start)
		waitForWatchReadiness(ready, resourceName)
		getOutput, version, err = oc.subnetRegistry.GetServices()
	default:
		log.Fatalf("Unknown resource %s for watch and get resource", resourceName)
	}
	if err != nil {
		return nil, err
	}

	start <- version

	return getOutput, nil
}
