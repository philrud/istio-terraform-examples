Basic example demonstrating how to setup Istio "Mesh Expansion" scenario on GKE/GCE using Terraform.

Specifically it does the following:
* Creates a brand new GKE cluster
* Initializes RBAC and k8s secrets so that kubectl can be used without affecting or depending on the local environment
* Installs Istio
* Creates a VM, installs necessary components and secrets to add it to the Istio mesh
* Installs test services on the mesh expansion VM and within the Istio mesh and ensures that they can reach each other
* Mesh Expansion VM uses Kubernetes `kube-dns` to resolve service DNS names

Prerequisites (should be available in PATH):
* Terraform 0.11
* Python 3.6+
* Helm

Example of how to apply the Terraform configuration providing required arguments:
```
$ terraform apply -var="prefix=test" -var="gcp_project=istio-test-230101" -var="gcp_credentials=~/account.json"
```

Caveats:
* If due to you corporate Google Cloud policies, a firewall rule allowing SSH access is being dropped faster than
  it takes to apply Terraform configuration, run `terraform apply` again -- it will recreate the firewall rule and
  finish provisioning.
