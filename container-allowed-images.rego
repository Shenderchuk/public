    package admission

    import data.k8s.matches
    
    ###############################################################################
    # https://raw.githubusercontent.com/Azure/azure-policy/master/built-in-references/KubernetesService/container-allowed-images/limited-preview/gatekeeperpolicy.rego
    # Policy : Container image name check if it matches the allowed patterns
    # e.g. should be from an organization registry. 
    #
    ###############################################################################
    deny[{
        "id": "{{AzurePolicyID}}",          # identifies type of violation
        "resource": {
            "kind": "pods",                 # identifies kind of resource
            "namespace": namespace,         # identifies namespace of resource
            "name": name                    # identifies name of resource
        },
        "resolution": {"message": msg},     # provides human-readable message to display
    }] {
        matches[["pods", namespace, name, matched_pod]]
        namespace != "testing"
        container = matched_pod.spec.containers[_]
        not re_match("{{policyParameters.allowedContainerImagesRegex}}", container.image)
        msg := sprintf("The operation was disallowed by policy ‘{{AzurePolicyID}}’. Error details: container image %q is not allowed.", [container.image])
    }