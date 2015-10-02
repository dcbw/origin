package flannelsdn

import (
	"github.com/golang/glog"
	"strings"

	kclient "k8s.io/kubernetes/pkg/client"
	knetwork "k8s.io/kubernetes/pkg/kubelet/network"
	"k8s.io/kubernetes/pkg/util/exec"
	"github.com/coreos/go-etcd/etcd"

	"github.com/openshift/openshift-sdn/pkg/ovssubnet"
	"github.com/openshift/openshift-sdn/plugins/osdn"
	osclient "github.com/openshift/origin/pkg/client"
)

func NetworkPluginName() string {
	return "redhat/openshift-ovs-flannel-sdn"
}

func Master(osClient *osclient.Client, kClient *kclient.Client, etcdClient *etcd.Client, clusterNetworkCIDR string, clusterBitsPerSubnet uint, serviceNetworkCIDR string) {
	osdnInterface := osdn.NewOsdnRegistryInterface(osClient, kClient)

	// get hostname from the gateway
	output, err := exec.New().Command("hostname", "-f").CombinedOutput()
	if err != nil {
		glog.Fatalf("SDN initialization failed: %v", err)
	}
	host := strings.TrimSpace(string(output))

	kc, err := ovssubnet.NewFlannelSDNController(&osdnInterface, etcdClient, host, "", nil)
	if err != nil {
		glog.Fatalf("SDN initialization failed: %v", err)
	}
	kc.AdminNamespaces = append(kc.AdminNamespaces, "default")
	err = kc.StartMaster(false, clusterNetworkCIDR, clusterBitsPerSubnet, serviceNetworkCIDR)
	if err != nil {
		glog.Fatalf("SDN initialization failed: %v", err)
	}
	glog.Infof("####### SDN initialized")
}

func Node(osClient *osclient.Client, kClient *kclient.Client, hostname string, publicIP string, ready chan struct{}, plugin knetwork.NetworkPlugin, mtu uint) {
	mp, ok := plugin.(*FlannelSDNPlugin)
	if !ok {
		glog.Fatalf("Failed to type cast provided plugin to a flannel-sdn type plugin")
	}
	osdnInterface := osdn.NewOsdnRegistryInterface(osClient, kClient)
	kc, err := ovssubnet.NewFlannelSDNController(&osdnInterface, nil, hostname, publicIP, ready)
	if err != nil {
		glog.Fatalf("SDN initialization failed: %v", err)
	}
	mp.OvsController = kc
	err = kc.StartNode(false, false, mtu)
	if err != nil {
		glog.Fatalf("SDN Node failed: %v", err)
	}
}
