#!/bin/bash

set -ex

lock_file=/var/lock/openshift-sdn.lock
mtu=$1

# Synchronize code execution with a file lock.
function lockwrap() {
    (
    flock 200
    "$@"
    ) 200>${lock_file}
}

function docker_network_config() {
    if [ -z "${DOCKER_NETWORK_OPTIONS}" ]; then
	DOCKER_NETWORK_OPTIONS="-b=lbr0 --mtu=${mtu}"
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
}

set +e
if ! setup_required; then
    echo "SDN setup not required."
    exit 140
fi
set -e

lockwrap setup
