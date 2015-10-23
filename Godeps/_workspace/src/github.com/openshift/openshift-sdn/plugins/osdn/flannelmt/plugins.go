package flannelmt

import (
	"fmt"
	"strconv"

	"github.com/golang/glog"

	"github.com/openshift/openshift-sdn/pkg/ovssubnet"
	knetwork "k8s.io/kubernetes/pkg/kubelet/network"
	kubeletTypes "k8s.io/kubernetes/pkg/kubelet/types"
	utilexec "k8s.io/kubernetes/pkg/util/exec"
)

const (
	initCmd     = "init"
	setUpCmd    = "setup"
	tearDownCmd = "teardown"
	statusCmd   = "status"
)

type FlannelMtPlugin struct {
	host          knetwork.Host
	OvsController *ovssubnet.OvsController
}

func GetKubeNetworkPlugin() knetwork.NetworkPlugin {
	return &FlannelMtPlugin{}
}

func (plugin *FlannelMtPlugin) getExecutable() string {
	return "openshift-sdn-flannelmt"
}

func (plugin *FlannelMtPlugin) Init(host knetwork.Host) error {
	plugin.host = host
	return nil
}

func (plugin *FlannelMtPlugin) Name() string {
	return NetworkPluginName()
}

func (plugin *FlannelMtPlugin) SetUpPod(namespace string, name string, id kubeletTypes.DockerID) error {
	vnid, found := plugin.OvsController.VNIDMap[namespace]
	if !found {
		return fmt.Errorf("Error fetching VNID for namespace: %s", namespace)
	}
	out, err := utilexec.New().Command(plugin.getExecutable(), setUpCmd, namespace, name, string(id), strconv.FormatUint(uint64(vnid), 10)).CombinedOutput()
	glog.V(5).Infof("SetUpPod 'flannelmt' network plugin output: %s, %v", string(out), err)
	return err
}

func (plugin *FlannelMtPlugin) TearDownPod(namespace string, name string, id kubeletTypes.DockerID) error {
	vnid, found := plugin.OvsController.VNIDMap[namespace]
	if !found {
		return fmt.Errorf("Error fetching VNID for namespace: %s", namespace)
	}
	out, err := utilexec.New().Command(plugin.getExecutable(), tearDownCmd, namespace, name, string(id), strconv.FormatUint(uint64(vnid), 10)).CombinedOutput()
	glog.V(5).Infof("TearDownPod 'flannelmt' network plugin output: %s, %v", string(out), err)
	return err
}

func (plugin *FlannelMtPlugin) Status(namespace string, name string, id kubeletTypes.DockerID) (*knetwork.PodNetworkStatus, error) {
	return nil, nil
}
