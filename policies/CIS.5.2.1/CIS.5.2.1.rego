package cis_5_2_1

import data.lib.kubernetes

violation[msg] {
	kubernetes.containers[container]
	container.securityContext.privileged
	msg = kubernetes.format(sprintf("%s in the %s %s is privileged", [container.name, kubernetes.kind, kubernetes.name]))
}

exception[rules] {
	kubernetes.pods[pod]
    pod.metadata.annotations["opa.policy.ignore/cis_5_2_1"]
	rules := ["violation"]
}
