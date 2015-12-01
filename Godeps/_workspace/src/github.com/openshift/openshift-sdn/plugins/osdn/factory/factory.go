package factory

import (
	"strings"

	"github.com/openshift/openshift-sdn/plugins/osdn"
	"github.com/openshift/openshift-sdn/plugins/osdn/api"

	"github.com/coreos/go-etcd/etcd"
	osclient "github.com/openshift/origin/pkg/client"
	oskserver "github.com/openshift/origin/pkg/cmd/server/kubernetes"
	kclient "k8s.io/kubernetes/pkg/client/unversioned"

	"github.com/openshift/openshift-sdn/plugins/osdn/ovs"
	"github.com/openshift/openshift-sdn/plugins/osdn/flannelmt"
)

// Call by higher layers to create the plugin instance
func NewPlugin(pluginType string, osClient *osclient.Client, kClient *kclient.Client, etcdClient *etcd.Client, hostname string, selfIP string, ready chan struct{}) (api.OsdnPlugin, oskserver.FilteringEndpointsConfigHandler, error) {
	switch strings.ToLower(pluginType) {
	case ovs.SingleTenantPluginName():
		return ovs.CreatePlugin(osdn.NewRegistry(osClient, kClient), false, hostname, selfIP, ready)
	case ovs.MultiTenantPluginName():
		return ovs.CreatePlugin(osdn.NewRegistry(osClient, kClient), true, hostname, selfIP, ready)
	case flannelmt.NetworkPluginName():
		return flannelmt.CreatePlugin(osdn.NewRegistry(osClient, kClient), etcdClient, hostname, selfIP, ready)
	}

	return nil, nil, nil
}
