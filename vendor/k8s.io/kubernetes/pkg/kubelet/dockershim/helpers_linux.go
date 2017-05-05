// +build linux

/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dockershim

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/blang/semver"
	dockertypes "github.com/docker/engine-api/types"
	dockercontainer "github.com/docker/engine-api/types/container"
	runtimeapi "k8s.io/kubernetes/pkg/kubelet/apis/cri/v1alpha1/runtime"

	sdnapi "github.com/openshift/origin/pkg/sdn/plugin"
)

func DefaultMemorySwap() int64 {
	return 0
}

func (ds *dockerService) getSecurityOpts(containerName string, sandboxConfig *runtimeapi.PodSandboxConfig, separator rune) ([]string, error) {
	// Apply seccomp options.
	seccompSecurityOpts, err := getSeccompSecurityOpts(containerName, sandboxConfig, ds.seccompProfileRoot, separator)
	if err != nil {
		return nil, fmt.Errorf("failed to generate seccomp security options for container %q: %v", containerName, err)
	}

	return seccompSecurityOpts, nil
}

func (ds *dockerService) updateCreateConfig(
	createConfig *dockertypes.ContainerCreateConfig,
	config *runtimeapi.ContainerConfig,
	sandboxConfig *runtimeapi.PodSandboxConfig,
	podSandboxID string, securityOptSep rune, apiVersion *semver.Version) error {
	// Apply Linux-specific options if applicable.
	if lc := config.GetLinux(); lc != nil {
		// *** NFV
		cpus := ""
		annotations := config.GetAnnotations()
		if cpuset, ok := annotations[sdnapi.NfvCPUAffinityAnnotation]; ok {
			sanitized := make([]string, 0, 2)
			split := strings.Split(cpuset, ",")
			for _, cpu := range split {
				num, err := strconv.ParseUint(cpu, 10, 32)
				if err != nil {
					return fmt.Errorf("failed to parse CPU affinity annotation '%s': %v", cpuset, err)
				}
				sanitized = append(sanitized, fmt.Sprintf("%d", num))
			}
			cpus = strings.Join(sanitized, ",")
		}

		// TODO: Check if the units are correct.
		// TODO: Can we assume the defaults are sane?
		rOpts := lc.GetResources()
		if rOpts != nil {
			createConfig.HostConfig.Resources = dockercontainer.Resources{
				Memory:     rOpts.MemoryLimitInBytes,
				MemorySwap: DefaultMemorySwap(),
				CPUShares:  rOpts.CpuShares,
				CPUQuota:   rOpts.CpuQuota,
				CPUPeriod:  rOpts.CpuPeriod,
				CpusetCpus: cpus,
			}
			createConfig.HostConfig.OomScoreAdj = int(rOpts.OomScoreAdj)
		} else if len(cpus) > 0 {
			createConfig.HostConfig.Resources = dockercontainer.Resources{
				CpusetCpus: cpus,
			}
		}
		// Note: ShmSize is handled in kube_docker_client.go

		// Apply security context.
		if err := applyContainerSecurityContext(lc, podSandboxID, createConfig.Config, createConfig.HostConfig, securityOptSep); err != nil {
			return fmt.Errorf("failed to apply container security context for container %q: %v", config.Metadata.Name, err)
		}
		modifyPIDNamespaceOverrides(ds.disableSharedPID, apiVersion, createConfig.HostConfig)
	}

	// Apply cgroupsParent derived from the sandbox config.
	if lc := sandboxConfig.GetLinux(); lc != nil {
		// Apply Cgroup options.
		cgroupParent, err := ds.GenerateExpectedCgroupParent(lc.CgroupParent)
		if err != nil {
			return fmt.Errorf("failed to generate cgroup parent in expected syntax for container %q: %v", config.Metadata.Name, err)
		}
		createConfig.HostConfig.CgroupParent = cgroupParent
	}

	return nil
}

func (ds *dockerService) determinePodIPBySandboxID(uid string) string {
	return ""
}
