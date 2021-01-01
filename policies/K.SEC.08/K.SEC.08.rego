package maicontainers_securitycontext_runasuser

import data.lib.kubernetes

# https://kubesec.io/basics/containers-securitycontext-runasuser/
violation[msg] {
	kubernetes.containers[container]
	container.securityContext.runAsUser == 0
	msg = kubernetes.format(sprintf("%s in the %s %s has a UID of 0", [container.name, kubernetes.kind, kubernetes.name]))
}

exception[rules] {
	kubernetes.pods[pod]
    pod.metadata.annotations["opa.policy.ignore/maicontainers_securitycontext_runasuser"]
	rules := ["violation"]
}
