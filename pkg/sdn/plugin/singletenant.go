package plugin

import (
	osapi "github.com/openshift/origin/pkg/sdn/api"
)

type singleTenantPlugin struct{}

func NewSingleTenantPlugin() osdnPolicy {
	return &singleTenantPlugin{}
}

func (sp *singleTenantPlugin) Name() string {
	return osapi.SingleTenantPluginName
}

func (sp *singleTenantPlugin) Start(node *OsdnNode) error {
	otx := node.ovs.NewTransaction()
	otx.AddFlow("table=80, priority=200, actions=output:NXM_NX_REG2[]")
	return otx.EndTransaction()
}

func (sp *singleTenantPlugin) AddNetNamespace(netns *osapi.NetNamespace, mcEnabled bool) {
}

func (sp *singleTenantPlugin) UpdateNetNamespace(netns *osapi.NetNamespace, mcEnabled bool, oldNetID uint32, oldMCEnabled bool) {
}

func (sp *singleTenantPlugin) DeleteNetNamespace(netns *osapi.NetNamespace, mcEnabled bool) {
}

func (sp *singleTenantPlugin) GetVNID(namespace string) (uint32, bool, error) {
	return 0, false, nil
}

func (sp *singleTenantPlugin) GetNamespaces(vnid uint32) []string {
	return nil
}

func (sp *singleTenantPlugin) RefVNID(vnid uint32) {
}

func (sp *singleTenantPlugin) UnrefVNID(vnid uint32) {
}
