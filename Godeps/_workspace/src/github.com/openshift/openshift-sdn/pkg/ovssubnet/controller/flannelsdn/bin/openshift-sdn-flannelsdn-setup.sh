#!/bin/bash

set -ex

lock_file=/var/lock/openshift-sdn.lock

# Synchronize code execution with a file lock.
function lockwrap() {
    (
    flock 200
    "$@"
    ) 200>${lock_file}
}

function docker_network_config() {
    if [ -z "${DOCKER_NETWORK_OPTIONS}" ]; then
	DOCKER_NETWORK_OPTIONS="-b=none"
    fi

    case "$1" in
	check)
	    if [ -f /.dockerinit ]; then
		# Assume supervisord-managed docker for docker-in-docker deployments
		conf=/etc/supervisord.conf
		if ! grep -q -s "DOCKER_DAEMON_ARGS=\"${DOCKER_NETWORK_OPTIONS}\"" $conf; then
		    return 1
		fi
	    else
		# Otherwise assume systemd-managed docker
		conf=/run/openshift-sdn/docker-network
		if ! grep -q -s "DOCKER_NETWORK_OPTIONS='${DOCKER_NETWORK_OPTIONS}'" $conf; then
		    return 1
		fi
	    fi
	    return 0
	    ;;

	update)
	    if [ -f /.dockerinit ]; then
		conf=/etc/supervisord.conf
		if [ ! -f $conf ]; then
		    echo "Running in docker but /etc/supervisord.conf not found." >&2
		    exit 1
		fi

		echo "Docker networking options have changed; manual restart required." >&2
		sed -i.bak -e \
		    "s+\(DOCKER_DAEMON_ARGS=\)\"\"+\1\"${DOCKER_NETWORK_OPTIONS}\"+" \
		    $conf
	    else
		mkdir -p /run/openshift-sdn
		cat <<EOF > /run/openshift-sdn/docker-network
# This file has been modified by openshift-sdn.

DOCKER_NETWORK_OPTIONS='${DOCKER_NETWORK_OPTIONS}'
EOF

		systemctl daemon-reload
		systemctl restart docker.service

		# disable iptables for lbr0
		# for kernel version 3.18+, module br_netfilter needs to be loaded upfront
		# for older ones, br_netfilter may not exist, but is covered by bridge (bridge-utils)
		#
		# This operation is assumed to have been performed in advance
		# for docker-in-docker deployments.
		modprobe br_netfilter || true
		sysctl -w net.bridge.bridge-nf-call-iptables=0
	    fi
	    ;;
    esac
}

function setup_required() {
    if ! docker_network_config check; then
        return 0
    fi
    return 1
}

function setup() {
    ## docker
    docker_network_config update

    # Cleanup docker0 since docker won't do it
    ip link set docker0 down || true
    brctl delbr docker0 || true

    # enable IP forwarding for ipv4 packets
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.conf.${TUN}.forwarding=1
}

set +e
if ! setup_required; then
    echo "SDN setup not required."
    exit 140
fi
set -e

lockwrap setup
