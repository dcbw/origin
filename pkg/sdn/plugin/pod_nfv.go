// +build linux

package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/openshift/origin/pkg/sdn/plugin/cniserver"

	"github.com/golang/glog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	kapi "k8s.io/kubernetes/pkg/api"
	kexec "k8s.io/kubernetes/pkg/util/exec"

	"github.com/containernetworking/cni/pkg/invoke"
	cniip "github.com/containernetworking/cni/pkg/ip"
	cniipam "github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	cnitypes "github.com/containernetworking/cni/pkg/types"
	cnicurrent "github.com/containernetworking/cni/pkg/types/current"

	"github.com/vishvananda/netlink"
)

type Route struct {
	// CIDR
	Dest string `json:"dest"`
	// Normal IP address
	NextHop string `json:"nextHop,omitempty"`
}

type IPAddr struct {
	IP      string `json:"ip"`
	Gateway string `json:"gateway,omitempty"`
}

type IPAM struct {
	// "static" config items
	IPs    []IPAddr `json:"ips,omitempty"`
	Routes []*Route `json:"routes,omitempty"`

	// "dhcpv4" config items
	Dhcp4    bool   `json:"dhcp4,omitempty"`
	ClientID string `json:"clientId,omitempty"`

	// Do IPv6 SLAAC configuration
	Slaac6 bool `json:"slaac6,omitempty"`
}

const (
	InterfaceTypeVlan     = "vlan"
	InterfaceTypePhysical = "physical"
	InterfaceTypeSRIOV    = "sriov"
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
	VfIndex int `json:"vfIndex,omitempty"`
	// vlan ID to assign to the virtual function
	VfVlan uint `json:"vfVlan,omitempty"`
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
	LocalAddressing    IPAM   `json:"localAddressing"`
	LocalContainerName string `json:"localContainerName"`
	// IP addressing for selected (other) pod's end of the veth pair
	RemoteAddressing    IPAM   `json:"remoteAddressing"`
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
	DhcpClient *os.Process
}

func NewNfvManager(exec kexec.Interface) *NfvManager {
	type dhcpIPAM struct {
		Type string `json:"type"`
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

	return &NfvManager{
		pods:       make(map[string]*nfvPod),
		dhcpConfig: dhcpConfig,
		exec:       exec,
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

func ipamSetupStatic(ipam IPAM, netns ns.NetNS, ifName string) (cnitypes.Result, error) {
	result := &cnicurrent.Result{}

	for _, ip := range ipam.IPs {
		addr, _, gw, isV4, err := parseIPAndGateway(ip.IP, ip.Gateway)
		if err != nil {
			return nil, err
		}

		v := "4"
		if !isV4 {
			v = "6"
		}
		result.IPs = append(result.IPs, &cnicurrent.IPConfig{
			Version: v,
			Address: addr,
			Gateway: gw,
		})
	}

	var err error
	for _, r := range ipam.Routes {
		cniRoute := &cnitypes.Route{}
		_, cniRoute.Dst, cniRoute.GW, _, err = parseIPAndGateway(r.Dest, r.NextHop)
		if err != nil {
			return nil, err
		}
		result.Routes = append(result.Routes, cniRoute)
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

const DhcpClientPidfile string = "/run/openshift-dhcp-client.pid"
const DhcpClientPath string = "/opt/cni/bin/dhcp"
const DhcpSocketPath string = "/run/cni/dhcp.sock"

func runDhcpClient() (*os.Process, error) {
	var out bytes.Buffer
	var oerr bytes.Buffer

	os.Remove(DhcpClientPidfile)
	cmd := exec.Command(DhcpClientPath, "daemon", "--pidfile", DhcpClientPidfile)
	cmd.Stdout = &out
	cmd.Stderr = &oerr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start DHCP client process: %v", err)
	}

	// Wait up to 5 seconds for the DHCP client socket path to exist
	for i := 0; i < 50; i++ {
		time.Sleep(time.Second / 10)
		if _, err := os.Stat(DhcpSocketPath); err == nil {
			return cmd.Process, nil
		}
	}
	cmd.Process.Kill()
	cmd.Process.Release()
	return nil, fmt.Errorf("timed out waiting for DHCP client daemon to start: %s / %s", out.String(), oerr.String())
}

func (m *NfvManager) KillDhcpClient() {
	p := m.DhcpClient
	if p == nil {
		p = findDhcpClient()
		if p == nil {
			return
		}
	}
	m.DhcpClient = nil
	p.Kill()
	p.Release()
	os.Remove(DhcpSocketPath)
	os.Remove(DhcpClientPidfile)
}

func findDhcpClient() *os.Process {
	data, err := ioutil.ReadFile(DhcpClientPidfile)
	if err != nil {
		return nil
	}

	success := false
	defer func(success *bool) {
		if !*success {
			os.Remove(DhcpClientPidfile)
		}
	}(&success)

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return nil
	}

	// Make sure the process is really a dhcp client
	data, err = ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil
	}
	if !strings.HasPrefix(string(data), DhcpClientPath) {
		return nil
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}

	success = true
	return process
}

func (m *NfvManager) ipamSetupDHCP(containerID string, netns ns.NetNS, containerIfname string) (cnitypes.Result, error) {
	// Find an existing client, or start one if needed
	if m.DhcpClient == nil {
		m.DhcpClient = findDhcpClient()
		if m.DhcpClient == nil {
			var err error
			m.DhcpClient, err = runDhcpClient()
			if err != nil {
				return nil, err
			}
		}
	}

	args := createDHCPArgs(containerID, netns, containerIfname, cniserver.CNI_ADD)
	result, err := invoke.ExecPluginWithResult(DhcpClientPath, m.dhcpConfig, args)
	if err != nil {
		return nil, fmt.Errorf("failed to run CNI DHCP IPAM ADD: %v", err)
	}

	return result, nil
}

func (m *NfvManager) ipamSetupSlaac(containerID string, netns ns.NetNS, containerIfname string) (cnitypes.Result, error) {
	result := &cnicurrent.Result{}

	if err := netns.Do(func(_ ns.NetNS) error {
		ch := make(chan netlink.AddrUpdate)
		done := make(chan struct{})
		defer close(done)

		if err := netlink.AddrSubscribe(ch, done); err != nil {
			return fmt.Errorf("failed to listen for netlink address events: %v", err)
		}

		link, err := netlink.LinkByName(containerIfname)
		if err != nil {
			return fmt.Errorf("failed to get container interface: %s", err)
		}

		if err := netlink.LinkSetDown(link); err != nil {
			return fmt.Errorf("failed to down container interface: %s", err)
		}
		// Toggle disable_ipv6 to force the kernel to listen for RAs again
		fileName := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", containerIfname)
		if err := ioutil.WriteFile(fileName, []byte("1"), 0644); err != nil {
			return fmt.Errorf("failed to toggle %q IPv6 off: %v", containerIfname, err)
		}
		time.Sleep(time.Second / 10)
		if err := ioutil.WriteFile(fileName, []byte("0"), 0644); err != nil {
			return fmt.Errorf("failed to toggle %q IPv6 on: %v", containerIfname, err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("failed to up container interface: %s", err)
		}

		// Wait up to 10s for a non-link-local address to show up
	loop:
		for {
			select {
			case update := <-ch:
				if update.LinkIndex == link.Attrs().Index &&
					update.LinkAddress.IP.To4() == nil &&
					update.NewAddr &&
					(update.Flags&syscall.IFA_F_TENTATIVE) == 0 &&
					(update.Flags&syscall.IFA_F_DADFAILED) == 0 &&
					!update.LinkAddress.IP.IsLinkLocalUnicast() &&
					!update.LinkAddress.IP.IsLinkLocalMulticast() {
					result.IPs = append(result.IPs, &cnicurrent.IPConfig{
						Version: "6",
						Address: update.LinkAddress,
					})
					break loop
				}
			case <-time.After(time.Second * 10):
				return fmt.Errorf("timed out waiting for IPv6 SLAAC address")
			}
		}

		// Look for an IPv6 default route through the container interface,
		// from which we grab the gateway
		routes, err := netlink.RouteList(link, netlink.FAMILY_V6)
		if err != nil {
			return fmt.Errorf("failed to list %q IPv6 routes: %v", err)
		}
		for _, r := range routes {
			if r.Dst != nil {
				ones, _ := r.Dst.Mask.Size()
				if ones != 0 {
					// Non-default route; ignore
					continue
				}
			}
			result.IPs[0].Gateway = r.Gw
			break
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return result, nil
}

func mergeCniResult(src cnitypes.Result, dest *cnicurrent.Result) error {
	from, err := cnicurrent.NewResultFromResult(src)
	if err != nil {
		return fmt.Errorf("failed to convert IPAM result for merge: %v", err)
	}

	dest.IPs = append(dest.IPs, from.IPs...)
	dest.Routes = append(dest.Routes, from.Routes...)
	return nil
}

func (m *NfvManager) ipamSetup(containerID string, netns ns.NetNS, ipam IPAM, link netlink.Link) (cnitypes.Result, error) {
	var (
		err       error
		tmpResult cnitypes.Result
	)

	result := &cnicurrent.Result{}

	if len(ipam.IPs) > 0 {
		tmpResult, err = ipamSetupStatic(ipam, netns, link.Attrs().Name)
		if err != nil {
			return nil, err
		}
		if err := mergeCniResult(tmpResult, result); err != nil {
			return nil, err
		}
	}

	if ipam.Dhcp4 {
		tmpResult, err = m.ipamSetupDHCP(containerID, netns, link.Attrs().Name)
		if err != nil {
			return nil, err
		}
		if err := mergeCniResult(tmpResult, result); err != nil {
			return nil, err
		}
	}

	if ipam.Slaac6 {
		tmpResult, err = m.ipamSetupSlaac(containerID, netns, link.Attrs().Name)
		if err != nil {
			return nil, err
		}
		if err := mergeCniResult(tmpResult, result); err != nil {
			return nil, err
		}
	}

	result.Interfaces = []*cnicurrent.Interface{
		{
			Name:    link.Attrs().Name,
			Sandbox: netns.Path(),
			Mac:     link.Attrs().HardwareAddr.String(),
		},
	}
	for _, ip := range result.IPs {
		// All IPs refer to the container interface for now
		ip.Interface = 0
		// Normalize IP addresses
		if ip.Address.IP.To4() != nil {
			ip.Address.IP = ip.Address.IP.To4()
		}
		if ip.Gateway.To4() != nil {
			ip.Gateway = ip.Gateway.To4()
		}
	}
	for _, route := range result.Routes {
		// Normalize route CIDRs
		if route.Dst.IP.To4() != nil {
			route.Dst.IP = route.Dst.IP.To4()
		}
		if route.GW.To4() != nil {
			route.GW = route.GW.To4()
		}
	}

	if err := netns.Do(func(_ ns.NetNS) error {
		return cniipam.ConfigureIface(link.Attrs().Name, result)
	}); err != nil {
		return nil, err
	}

	return result, nil
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
			if chain.LocalAddressing.Slaac6 ||
				chain.LocalAddressing.Dhcp4 ||
				chain.RemoteAddressing.Slaac6 ||
				chain.RemoteAddressing.Dhcp4 {
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

	var fromVeth, toVeth net.Interface
	var fromVethLink, toVethLink netlink.Link
	var err error
	err = fromNetns.Do(func(_ ns.NetNS) error {
		toVeth, fromVeth, err = cniip.SetupVeth(chain.LocalContainerName, int(mtu), toNetns)
		if err != nil {
			return err
		}
		fromVethLink, err = netlink.LinkByName(fromVeth.Name)
		return err
	})
	if err != nil {
		return err
	}

	if _, err := m.ipamSetup("", fromNetns, chain.LocalAddressing, fromVethLink); err != nil {
		return fmt.Errorf("failed to set up local chain: %v", err)
	}

	// Rename remote side
	err = toNetns.Do(func(_ ns.NetNS) error {
		toVethLink, err = netlink.LinkByName(toVeth.Name)
		if err != nil {
			return fmt.Errorf("failed to retrieve remote container link %q: %v", toVeth.Name, err)
		}
		if err := netlink.LinkSetDown(toVethLink); err != nil {
			return fmt.Errorf("failed to down remote container link %q: %v", toVeth.Name, err)
		}
		if err := netlink.LinkSetName(toVethLink, chain.RemoteContainerName); err != nil {
			return fmt.Errorf("failed to rename remote container link %q to %q: %v", toVeth.Name, chain.RemoteContainerName, err)
		}
		toVethLink, _ = netlink.LinkByName(chain.RemoteContainerName)
		if err != nil {
			return fmt.Errorf("failed to refetch remote container link %q: %v", chain.RemoteContainerName, err)
		}
		if err := netlink.LinkSetUp(toVethLink); err != nil {
			return fmt.Errorf("failed to up remote container link %q: %v", toVeth.Name, err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if _, err := m.ipamSetup("", toNetns, chain.RemoteAddressing, toVethLink); err != nil {
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

func (m *NfvManager) nfvSetup(req *cniserver.PodRequest, pod *kapi.Pod) (bool, cnitypes.Result, error) {
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

	var firstResult cnitypes.Result
	for _, name := range netNames {
		var link netlink.Link
		var err error

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
		result, err := m.ipamSetup(req.SandboxID, netns, net.Addressing, link)
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
	if netns != nil {
		linkName := network.Interface.ContainerName
		if err := netns.Do(func(_ ns.NetNS) error {
			vf, err := netlink.LinkByName(linkName)
			if err != nil {
				return fmt.Errorf("failed to refetch link %q: %v", linkName, err)
			}

			return vfSetDynamic(vf, false)
		}); err != nil {
			return err
		}
	}

	return nil
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
		if net.Addressing.Dhcp4 {
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
