package containers_securitycontext_runasnonroot_true

import data.lib.kubernetes

# https://kubesec.io/basics/containers-securitycontext-runasnonroot-true/
violation[msg] {
	kubernetes.containers[container]
	not container.securityContext.runAsNonRoot
	msg = kubernetes.format(sprintf("%s in the %s %s is running as root", [container.name, kubernetes.kind, kubernetes.name]))
}

exception[rules] {
	kubernetes.pods[pod]
    pod.metadata.annotations["opa.policy.ignore/containers_securitycontext_runasnonroot_true"]
	rules := ["violation"]
}
