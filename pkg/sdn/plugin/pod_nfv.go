// +build linux

package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/openshift/origin/pkg/sdn/plugin/cniserver"

	"github.com/golang/glog"

	kapi "k8s.io/kubernetes/pkg/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	kexec "k8s.io/kubernetes/pkg/util/exec"

	"github.com/containernetworking/cni/pkg/invoke"
	cniip "github.com/containernetworking/cni/pkg/ip"
	cniipam "github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	cnitypes "github.com/containernetworking/cni/pkg/types"

	"github.com/vishvananda/netlink"
)

type Route struct {
	// CIDR
	Dest string `json:"dest"`
	// Normal IP address
	NextHop string `json:"nextHop,omitempty"`
}

const (
	IPAMTypeStatic = "static"
	IPAMTypeAuto   = "auto"
	IPAMTypeNone   = "none"
)

type IPAddr struct {
	IP      string   `json:"ip"`
	Gateway string   `json:"gateway,omitempty"`
}

type IPAM struct {
	// "static" - static IP; requires CIDR, gateway, optional routes
	// "auto" - use DHCP (interfaces); optional ClientID
	// "none" - no addressing
	Type string `json:"type"`

	// "static" config items
	IPs    []IPAddr `json:"ips,omitempty"`
	Routes []*Route `json:"routes,omitempty"`

	// "dhcp" config items
	ClientID string `json:"clientId,omitempty"`
}

const (
	InterfaceTypeVlan = "vlan"
	InterfaceTypePhysical = "physical"
	InterfaceTypeSRIOV = "sriov"
)

type InterfaceSpec struct {
	// "vlan" - create a VLAN; requires physical options too
	// "physical" - use a physical NIC
	// "sriov" - use a Virtual Function (VF) of a physical NIC
	Type string `json:"type"`

	// Interface name inside container
	ContainerName string `json:"containerName"`

	// "vlan" options
	VlanID uint `json:"vlanId,omitempty"`

	// "physical" options
	Ifname     string `json:"ifname,omitempty"`
	MacAddress string `json:"macAddress,omitempty"`
	// ex: "/sys/devices/pci0000:00/0000:00:19.0"
	KernelPath string `json:"kernelPath,omitempty"`

	// "sriov" options
	// index # of the virtual function (VF) to use; if missing the next VF
	// not in-use by OpenShift will be used.
	VfIndex    int `json:"vfIndex,omitempty"`
	// vlan ID to assign to the virtual function
	VfVlan     uint `json:"vfVlan,omitempty"`
	// MAC address to assign to the VF
	VfMacAddress string `json:"vfMacAddress:omitempty"`
}

type Network struct {
	Addressing IPAM          `json:"addressing"`
	Interface  InterfaceSpec `json:"interface"`
}

type ServiceFunctionChain struct {
	// Human name for chain; otherwise unused
	Name string

	// Label selector of another pod to create a veth pair to
	ToPod map[string]string `json:"toPod,omitempty"`

	// IP addressoing for this pod's end of the veth pair
	LocalAddressing    IPAM `json:"localAddressing"`
	LocalContainerName string `json:"localContainerName"`
	// IP addressing for selected (other) pod's end of the veth pair
	RemoteAddressing    IPAM `json:"remoteAddressing"`
	RemoteContainerName string `json:"remoteContainerName"`

	MTU uint `json:"mtu,omitempty"`
}

const (
	NfvNetworksAnnotation             = "pod.network.openshift.io/nfv-networks"
	NfvServiceFunctionChainAnnotation = "pod.network.openshift.io/nfv-service-function-chains"
	NfvSelectSDNAnnotation            = "pod.network.openshift.io/nfv-select-sdn"
	NfvCPUAffinityAnnotation          = "pod.network.openshift.io/nfv-cpu-affinity"
)

type nfvPod struct {
	// Save annotations so we can do the right thing on teardown
	annotations map[string]string
	labels      map[string]string
	netnsPath   string
	containerID string
}

type NfvManager struct {
	pods       map[string]*nfvPod
	dhcpConfig []byte
	exec       kexec.Interface
	origNS     ns.NetNS
}

func NewNfvManager(exec kexec.Interface, origNS ns.NetNS) *NfvManager {
	type dhcpIPAM struct {
		Type   string           `json:"type"`
		// TODO: clientID somehow
	}

	type cniNetworkConfig struct {
		Name string    `json:"name"`
		Type string    `json:"type"`
		IPAM *dhcpIPAM `json:"ipam"`
	}

	dhcpConfig, _ := json.Marshal(&cniNetworkConfig{
		Name: "openshift-sdn",
		Type: "openshift-sdn",
		IPAM: &dhcpIPAM{
			Type: "dhcp",
		},
	})

	if origNS == nil {
		origNS, _ = ns.GetCurrentNS()
	}

	return &NfvManager{
		pods:       make(map[string]*nfvPod),
		dhcpConfig: dhcpConfig,
		exec:       exec,
		origNS:     origNS,
	}
}

func podWantsSDN(annotations *map[string]string) bool {
	// Pods always get the SDN unless they specifically opt out
	val, ok := (*annotations)[NfvSelectSDNAnnotation]
	if ok && val == "false" {
		return false
	}
	return true
}

func findPhysdev(network *Network) (netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("failed to list node links: %v", err)
	}

	if len(network.Interface.Ifname) > 0 {
		if m, err := netlink.LinkByName(network.Interface.Ifname); err == nil {
			return m, nil
		}
	} else if len(network.Interface.MacAddress) > 0 {
		hwAddr, err := net.ParseMAC(network.Interface.MacAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to parse MAC address %q: %v", network.Interface.MacAddress, err)
		}

		for _, link := range links {
			if bytes.Equal(link.Attrs().HardwareAddr, hwAddr) {
				return link, nil
			}
		}
	} else if len(network.Interface.KernelPath) > 0 {
		if !filepath.IsAbs(network.Interface.KernelPath) || !strings.HasPrefix(network.Interface.KernelPath, "/sys/devices/") {
			return nil, fmt.Errorf("kernel device path %q must be absolute and begin with /sys/devices/", network.Interface.KernelPath)
		}
		netDir := filepath.Join(network.Interface.KernelPath, "net")
		files, err := ioutil.ReadDir(netDir)
		if err != nil {
			return nil, fmt.Errorf("failed to find network devices at %q", netDir)
		}

		// Grab the first device from eg /sys/devices/pci0000:00/0000:00:19.0/net
		for _, file := range files {
			// Make sure it's really an interface
			for _, l := range links {
				if file.Name() == l.Attrs().Name {
					return l, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("failed to find physical interface from network %#v", network)
}

func ifaceRename(oldName, newName string, netns ns.NetNS) (netlink.Link, error) {
	var newLink netlink.Link
	if err := netns.Do(func(_ ns.NetNS) error {
		oldLink, err := netlink.LinkByName(oldName)
		if err != nil {
			return fmt.Errorf("failed to refetch link %q: %v", oldName, err)
		}

		if err := netlink.LinkSetName(oldLink, newName); err != nil {
			return fmt.Errorf("failed to rename link %q to %q: %v", oldName, newName, err)
		}

		newLink, err = netlink.LinkByName(newName)
		if err != nil {
			return fmt.Errorf("failed to fetch link %q after rename: %v", newName, err)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return newLink, nil
}

func vlanSetup(netns ns.NetNS, network *Network) (netlink.Link, error) {
	master, err := findPhysdev(network)
	if err != nil {
		return nil, err
	}

	tmpName, err := cniip.RandomVethName()
	if err != nil {
		return nil, fmt.Errorf("unable to create temporary name for VLAN interface: %v", err)
	}

	v := &netlink.Vlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        tmpName,
			ParentIndex: master.Attrs().Index,
			Namespace:   netlink.NsFd(int(netns.Fd())),
		},
		VlanId: int(network.Interface.VlanID),
	}

	if err := netlink.LinkAdd(v); err != nil {
		return nil, fmt.Errorf("failed to create vlan: %v", err)
	}

	return ifaceRename(tmpName, network.Interface.ContainerName, netns)
}

func physicalSetup(netns ns.NetNS, network *Network) (netlink.Link, error) {
	master, err := findPhysdev(network)
	if err != nil {
		return nil, err
	}

	if err := netlink.LinkSetNsFd(master, int(netns.Fd())); err != nil {
		return nil, err
	}

	return ifaceRename(master.Attrs().Name, network.Interface.ContainerName, netns)
}

func vfnToLink(master netlink.Link, links []netlink.Link, vfn string) (netlink.Link, error) {
	vfNetPath := fmt.Sprintf("/sys/class/net/%s/device/%s/net", master.Attrs().Name, vfn)
	files, err := ioutil.ReadDir(vfNetPath)
	if err != nil {
		return nil, fmt.Errorf("failed to find SRIOV VF at %q", vfNetPath)
	}
	
	for _, file := range files {
		// Make sure it's really an interface
		for _, l := range links {
			if file.Name() == l.Attrs().Name {
				return l, nil
			}
		}
	}		

	return nil, fmt.Errorf("failed to find SRIOV VF %q", vfn)
}

func vfGetDynamic(link netlink.Link) (bool, error) {
	output, err := kexec.New().Command("ip", "link", "show", "dev", link.Attrs().Name).CombinedOutput()	
	if err != nil {
		return false, fmt.Errorf("failed to get flags for %q: %v", link.Attrs().Name, err)
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 {
		return false, fmt.Errorf("failed to parse ip output (not enough lines): %q", string(output))
	}
	return strings.Contains(lines[0], "DYNAMIC"), nil
}

func vfSetDynamic(link netlink.Link, dynamic bool) error {
	val := "on"
	if !dynamic {
		val = "off"
	}
	if _, err := kexec.New().Command("ip", "link", "set", "dev", link.Attrs().Name, "dynamic", val).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set flags for %q: %v", link.Attrs().Name, err)
	}

	return nil
}

func sriovGetVf(master netlink.Link, network *Network) (netlink.Link, uint, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list node links: %v", err)
	}

	if network.Interface.VfIndex >= 0 {
		vfn := fmt.Sprintf("virtfn%d", network.Interface.VfIndex)
		vf, err := vfnToLink(master, links, vfn)
		if err != nil {
			return nil, 0, err
		}

		dynamic, err := vfGetDynamic(vf)
		if err != nil {
			return nil, 0, err
		} else if dynamic {
			return nil, 0, fmt.Errorf("SRIOV VF %q is already in-use by a container", vf.Attrs().Name)
		}

		return vf, uint(network.Interface.VfIndex), nil
	}

	// Otherwise find a free VF
	masterPath := fmt.Sprintf("/sys/class/net/%s/device", master.Attrs().Name, network.Interface.VfIndex)
	files, err := ioutil.ReadDir(masterPath)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read master net device directory %q", masterPath)
	}
	haveVirtfns := false
	for _, file := range files {
		if !strings.HasPrefix(file.Name(), "virtfn") {
			continue
		}

		haveVirtfns = true
		vf, err := vfnToLink(master, links, file.Name())
		if err != nil {
			continue
		}

		// Check for the absence IFF_DYNAMIC flag, which we take to mean
		// we're not already using this VF for another container
		dynamic, err := vfGetDynamic(vf)
		if err != nil {
			glog.Warningf("%v", err)
		} else if !dynamic {
			vfnum := file.Name()[6:]
			vfidx, err := strconv.Atoi(vfnum)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to get VF index from %q: %v", vfnum, err)
			}
			return vf, uint(vfidx), nil
		}
	}

	if !haveVirtfns {
		return nil, 0, fmt.Errorf("failed to find any SRIOV 'virtfn' links in %q", masterPath)
	}

	return nil, 0, fmt.Errorf("failed to find a free SRIOV VF of %q", master.Attrs().Name)
}

func sriovSetup(netns ns.NetNS, network *Network) (netlink.Link, error) {
	master, err := findPhysdev(network)
	if err != nil {
		return nil, err
	}

	vf, vfidx, err := sriovGetVf(master, network)
	if err != nil {
		return nil, err
	}

	// Mark this VF as in-use by a container
	if err := vfSetDynamic(vf, true); err != nil {
		return nil, err
	}

	if err := netlink.LinkSetVfVlan(master, int(vfidx), int(network.Interface.VfVlan)); err != nil {
		return nil, fmt.Errorf("failed to SRIOV VF %q VLAN to %d: %v", vf.Attrs().Name, network.Interface.VfVlan, err)
	}

	if network.Interface.VfMacAddress != "" {
		hwaddr, err := net.ParseMAC(network.Interface.VfMacAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SRIOV VF %q MAC address %q: %v", vf.Attrs().Name, network.Interface.VfMacAddress, err)
		}

		if err := netlink.LinkSetVfHardwareAddr(master, int(vfidx), hwaddr); err != nil {
			return nil, fmt.Errorf("failed to SRIOV VF %q MAC address to %q: %v", vf.Attrs().Name, network.Interface.VfMacAddress, err)
		}
	}

	if err := netlink.LinkSetNsFd(vf, int(netns.Fd())); err != nil {
		return nil, err
	}

	return ifaceRename(vf.Attrs().Name, network.Interface.ContainerName, netns)
}

// Parses a CIDR and a gateway IP address and returns (a) a CIDR consisting of the
// the IP address and given mask, (b) a CIDR consisting of the IP network and
// the given mask, (c) the gateway IP address, and (d) whether it's IPv4 or v6
func parseIPAndGateway(cidr, gateway string) (net.IPNet, net.IPNet, net.IP, bool, error) {
	addr, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return net.IPNet{}, net.IPNet{}, nil, false, fmt.Errorf("failed to parse IP address %q", cidr)
	}
	isV4 := false
	if addr.To4() != nil {
		addr = addr.To4()
		ipnet.IP = ipnet.IP.To4()
		isV4 = true
	}
	ip := *ipnet
	ip.IP = addr

	if len(gateway) > 0 {
		addr = net.ParseIP(gateway)
		if addr == nil {
			return net.IPNet{}, net.IPNet{}, nil, false, fmt.Errorf("failed to parse gateway %q", gateway)
		}
		if isV4 {
			if addr.To4() == nil {
				return net.IPNet{}, net.IPNet{}, nil, false, fmt.Errorf("failed to parse IPv4 gateway %q", gateway)
			}
			addr = addr.To4()
		} else {
			if addr.To4() != nil {
				return net.IPNet{}, net.IPNet{}, nil, false, fmt.Errorf("failed to parse IPv6 gateway %q", gateway)
			}
		}
	}

	return ip, *ipnet, addr, isV4, nil
}

func ipamSetupStatic(ipam IPAM, netns ns.NetNS, ifName string) (*cnitypes.Result, error) {
	result := &cnitypes.Result{}
	if err := netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q: %v", ifName, err)
		}

		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to set %q UP: %v", ifName, err)
		}

		// Add all addresses
		var isV4 bool
		for _, ip := range ipam.IPs {
			addr, _, gw, isV4, err := parseIPAndGateway(ip.IP, ip.Gateway)
			if err != nil {
				return err
			}

			ipconfig := &cnitypes.IPConfig{
				IP:      addr,
				Gateway: gw,
			}

			if isV4 && result.IP4 == nil {
				result.IP4 = ipconfig
			} else if !isV4 && result.IP6 == nil {
				result.IP6 = ipconfig
			}

			nladdr := &netlink.Addr{IPNet: &addr, Label: ""}
			if err = netlink.AddrAdd(link, nladdr); err != nil {
				return fmt.Errorf("failed to add IP addr to %q: %v", ifName, err)
			}
		}

		// Add all routes
		for _, r := range ipam.Routes {
			cniRoute := cnitypes.Route{}
			_, cniRoute.Dst, cniRoute.GW, isV4, err = parseIPAndGateway(r.Dest, r.NextHop)
			if err != nil {
				return err
			}

			gw := cniRoute.GW
			if isV4 && result.IP4 != nil {
				result.IP4.Routes = append(result.IP4.Routes, cniRoute)
				if gw == nil {
					gw = result.IP4.Gateway
				}
			} else if !isV4 && result.IP6 != nil {
				result.IP6.Routes = append(result.IP6.Routes, cniRoute)
				if gw == nil {
					gw = result.IP6.Gateway
				}
			}

			if err = cniip.AddRoute(&cniRoute.Dst, gw, link); err != nil {
				// we skip over duplicate routes as we assume the first one wins
				if !os.IsExist(err) {
					return fmt.Errorf("failed to add route '%v via %v dev %v': %v", cniRoute.Dst, gw, ifName, err)
				}
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return result, nil
}

func createDHCPArgs(containerID string, netns ns.NetNS, ifName string, action cniserver.CNICommand) *invoke.Args {
	var netnsPath string
	if netns != nil {
		netnsPath = netns.Path()
	}
	return &invoke.Args{
		Command:     string(action),
		ContainerID: containerID,
		NetNS:       netnsPath,
		IfName:      ifName,
		Path:        "/opt/cni/bin",
	}
}

func (m *NfvManager) ipamSetupDHCP(containerID string, netns ns.NetNS, containerIfname string) (*cnitypes.Result, error) {
	args := createDHCPArgs(containerID, netns, containerIfname, cniserver.CNI_ADD)
	result, err := invoke.ExecPluginWithResult("/opt/cni/bin/dhcp", m.dhcpConfig, args)
	if err != nil {
		return nil, fmt.Errorf("failed to run CNI DHCP IPAM ADD: %v", err)
	}

	if result.IP4 == nil {
		return nil, fmt.Errorf("failed to obtain IP address from CNI DHCP IPAM")
	}

	if err := netns.Do(func(_ ns.NetNS) error {
		return cniipam.ConfigureIface(containerIfname, result)
	}); err != nil {
		return nil, err
	}

	return result, nil
}

func (m *NfvManager) ipamSetup(containerID string, netns ns.NetNS, ipam IPAM, link netlink.Link) (*cnitypes.Result, error) {
	var err error

	result := &cnitypes.Result{}
	switch ipam.Type {
	case IPAMTypeStatic:
		result, err = ipamSetupStatic(ipam, netns, link.Attrs().Name)
	case IPAMTypeAuto:
		result, err = m.ipamSetupDHCP(containerID, netns, link.Attrs().Name)
	case IPAMTypeNone:
		return result, nil
	}

	return result, err
}

func getPodNetworksAndChains(annotations *map[string]string) (map[string]*Network, []*ServiceFunctionChain, error) {
	networks := map[string]*Network{}
	chains := []*ServiceFunctionChain{}

	val, ok := (*annotations)[NfvNetworksAnnotation]
	if ok && len(val) > 0 {
		if err := json.Unmarshal([]byte(val), &networks); err != nil {
			return nil, nil, fmt.Errorf("error parsing NFV network annotation JSON: %v", err)
		}
	}

	val, ok = (*annotations)[NfvServiceFunctionChainAnnotation]
	if ok && len(val) > 0 {
		if err := json.Unmarshal([]byte(val), &chains); err != nil {
			return nil, nil, fmt.Errorf("error parsing NFV SFC annotation JSON: %v", err)
		}
		for _, chain := range chains {
			if chain.LocalAddressing.Type == IPAMTypeAuto || chain.RemoteAddressing.Type == IPAMTypeAuto {
				return nil, nil, fmt.Errorf("IPAM type 'auto' not allowed for chains")
			}
		}
	}

	return networks, chains, nil
}

func (m *NfvManager) setupChain(fromNetns, toNetns ns.NetNS, chain *ServiceFunctionChain) error {
	mtu := chain.MTU
	if mtu == 0 {
		mtu = 65535
	}

	var fromVeth, toVeth netlink.Link
	var err error
	err = fromNetns.Do(func(_ ns.NetNS) error {
		toVeth, fromVeth, err = cniip.SetupVeth(chain.LocalContainerName, int(mtu), toNetns)
		return err
	})
	if err != nil {
		return err
	}

	if _, err := m.ipamSetup("", fromNetns, chain.LocalAddressing, fromVeth); err != nil {
		return fmt.Errorf("failed to set up local chain: %v", err)
	}

	// Rename remote side
	err = toNetns.Do(func(_ ns.NetNS) error {
		toVeth, err = netlink.LinkByName(toVeth.Attrs().Name)
		if err != nil {
			return fmt.Errorf("failed to retrieve remote container link %q: %v", toVeth.Attrs().Name, err)
		}
		if err := netlink.LinkSetDown(toVeth); err != nil {
			return fmt.Errorf("failed to down remote container link %q: %v", toVeth.Attrs().Name, err)
		}
		if err := netlink.LinkSetName(toVeth, chain.RemoteContainerName); err != nil {
			return fmt.Errorf("failed to rename remote container link %q to %q: %v", toVeth.Attrs().Name, chain.RemoteContainerName, err)
		}
		toVeth, _ = netlink.LinkByName(chain.RemoteContainerName)
		if err != nil {
			return fmt.Errorf("failed to refetch remote container link %q: %v", chain.RemoteContainerName, err)
		}
		if err := netlink.LinkSetUp(toVeth); err != nil {
			return fmt.Errorf("failed to up remote container link %q: %v", toVeth.Attrs().Name, err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if _, err := m.ipamSetup("", toNetns, chain.RemoteAddressing, toVeth); err != nil {
		return fmt.Errorf("failed to set up remote chain: %v", err)
	}

	return nil

}

func (m *NfvManager) setupChainTo(fromNetns ns.NetNS, toPod *nfvPod, chain *ServiceFunctionChain) error {
	toNetns, err := ns.GetNS(toPod.netnsPath)
	if err != nil {
		return fmt.Errorf("failed to get destination container netns: %v", err)
	}
	defer toNetns.Close()

	return m.setupChain(fromNetns, toNetns, chain)
}

func (m *NfvManager) setupChainFrom(fromPod *nfvPod, toNetns ns.NetNS, chain *ServiceFunctionChain) error {
	fromNetns, err := ns.GetNS(fromPod.netnsPath)
	if err != nil {
		return fmt.Errorf("failed to get destination container netns: %v", err)
	}
	defer fromNetns.Close()

	return m.setupChain(fromNetns, toNetns, chain)
}

func (m *NfvManager) nfvSetup(req *cniserver.PodRequest, pod *kapi.Pod) (bool, *cnitypes.Result, error) {
	doSDN := podWantsSDN(&pod.Annotations)

	networks, chains, err := getPodNetworksAndChains(&pod.Annotations)
	if err != nil {
		return false, nil, err
	}

	netns, err := ns.GetNS(req.Netns)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get container netns: %v", err)
	}
	defer netns.Close()

	podKey := getPodKey(req)
	if _, ok := m.pods[podKey]; ok {
		// Shouldn't ever happen...
		return false, nil, fmt.Errorf("pod already set up!")
	}
	thisPod := &nfvPod{
		annotations: pod.Annotations,
		labels:      pod.Labels,
		netnsPath:   req.Netns,
	}
	m.pods[podKey] = thisPod

	// Create alphabetized array of networks to ensure setup happens
	// in deterministic order
	netNames := make([]string, 0, len(networks))
	for name := range networks {
		netNames = append(netNames, name)
	}
	sort.Strings(netNames)

	var firstResult *cnitypes.Result
	for _, name := range netNames {
		var link netlink.Link
		var err  error

		net := networks[name]

		// set up the interface in the container netns
		switch net.Interface.Type {
		case InterfaceTypeVlan:
			link, err = vlanSetup(netns, net)
		case InterfaceTypePhysical:
			link, err = physicalSetup(netns, net)
		case InterfaceTypeSRIOV:
			link, err = sriovSetup(netns, net)
		default:
			return false, nil, fmt.Errorf("invalid NFV interface type %s", net.Interface.Type)
		}

		if err != nil {
			return false, nil, err
		}

		// set up IPAM on the container interface
		result, err := m.ipamSetup(req.SandboxID, netns, net.Addressing, link);
		if err != nil {
			return false, nil, err
		}
		if firstResult == nil {
			firstResult = result
		}
	}

	// Set up chains from this pod to other pods, if the other pod already exists
	for _, chain := range chains {
		for key, otherPod := range m.pods {
			if key == podKey {
				continue
			}

			sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
				MatchLabels: chain.ToPod,
			})
			if err == nil && sel.Matches(labels.Set(otherPod.labels)) {
				if err := m.setupChainTo(netns, otherPod, chain); err != nil {
					return false, nil, fmt.Errorf("failed to set up chain: %v", err)
				}
			}
		}
	}

	// Set up chains from other pods to this pod, now that this pod exists
	for key, otherPod := range m.pods {
		if key == podKey {
			continue
		}

		// Does the other pod select this pod in a chain?
		_, chains, err := getPodNetworksAndChains(&otherPod.annotations)
		if err != nil {
			continue
		}

		for _, chain := range chains {
			sel, err := metav1.LabelSelectorAsSelector(&metav1.LabelSelector{
				MatchLabels: chain.ToPod,
			})
			if err == nil && sel.Matches(labels.Set(pod.Labels)) {
				if err := m.setupChainFrom(otherPod, netns, chain); err != nil {
					return false, nil, fmt.Errorf("failed to set up chain: %v", err)
				}
			}
		}
	}

	return doSDN, firstResult, nil
}

func (m *NfvManager) nfvUpdate(req *cniserver.PodRequest, pod *kapi.Pod) (bool, error) {
	return podWantsSDN(&pod.Annotations), nil
}

func (m *NfvManager) dhcpTeardown(req *cniserver.PodRequest, network *Network, netns ns.NetNS) error {
	args := createDHCPArgs(req.SandboxID, netns, network.Interface.ContainerName, cniserver.CNI_DEL)
	err := invoke.ExecPluginWithoutResult("/opt/cni/bin/dhcp", m.dhcpConfig, args)
	if err != nil {
		if netns != nil {
			return fmt.Errorf("failed to run CNI IPAM DEL: %v", err)
		}
		// If the NetNS is no longer valid ignore any errors; DHCP needs
		// to access the NetNS to send the release, and obviously that fails
		return nil
	}

	return nil
}

func (m *NfvManager) sriovTeardown(network *Network, netns ns.NetNS) error {
	master, err := findPhysdev(network)
	if err != nil {
		return err
	}

	if netns != nil {
		// Move the SRIOV link back to the parent netns so we can
		// clear the DYNAMIC flag
		linkName := network.Interface.ContainerName
		if err := netns.Do(func(_ ns.NetNS) error {
			vf, err := netlink.LinkByName(linkName)
			if err != nil {
				return fmt.Errorf("failed to refetch link %q: %v", linkName, err)
			}

			if err := netlink.LinkSetDown(vf); err != nil {
				return fmt.Errorf("failed to set link %q down: %v", linkName, err)
			}

			if err := netlink.LinkSetNsFd(vf, int(m.origNS.Fd())); err != nil {
				return fmt.Errorf("failed to set link %q to original netns: %v", err)
			}
			return nil
		}); err != nil {
			return err
		}
	}

	vf, _, err := sriovGetVf(master, network)
	if err != nil {
		return err
	}

	return vfSetDynamic(vf, false)
}

func (m *NfvManager) nfvTeardown(req *cniserver.PodRequest, netnsValid bool) (bool, error) {
	podKey := getPodKey(req)
	nfvPod, ok := m.pods[podKey]
	if !ok {
		// No NFV setup
		return true, nil
	}

	hasSDN := podWantsSDN(&nfvPod.annotations)
	networks, chains, err := getPodNetworksAndChains(&nfvPod.annotations)
	if err != nil {
		return false, err
	} else if len(networks) == 0 && len(chains) == 0 {
		return hasSDN, nil
	}
	delete(m.pods, podKey)

	var netns ns.NetNS
	if netnsValid {
		netns, err = ns.GetNS(req.Netns)
		if err != nil {
			return false, fmt.Errorf("failed to get container netns: %v", err)
		}
		defer netns.Close()
	}

	for _, net := range networks {
		if net.Addressing.Type == IPAMTypeAuto {
			if err := m.dhcpTeardown(req, net, netns); err != nil {
				glog.Warningf("Failed to tear down DHCP IPAM for %q/%q: %v", req.PodNamespace, req.PodName, err)
			}
		}

		if net.Interface.Type == InterfaceTypeSRIOV {
			if err := m.sriovTeardown(net, netns); err != nil {
				glog.Warningf("Failed to tear down SRIOV VF for %q/%q: %v", req.PodNamespace, req.PodName, err)
			}
		}
	}

	return hasSDN, nil
}
