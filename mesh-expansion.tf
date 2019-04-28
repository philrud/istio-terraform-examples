# Input arguments
#
# Can be passed via command line arguments (example: `-var="key=value"`), environment variables
# (example: `TF_VAR_key=value`) or `.tfvars`-files (example: `-var-file="hcl-format-keys-and-vals.tfvars"`).

variable "gcp_project" {
  type = "string"
  default = "istio-test-230101"
  description = "PROJECT_ID of GCP Project (e.g. `istio-test-230101`)"
}
variable "gcp_credentials" {
  type = "string"
  default = "~/account.json"
  description = "Path to a GCP service account JSON key file (can be generated/obtained from 'IAM & Admin' / 'Service Accounts')"
}
variable "prefix" {
  type = "string"
  default = "test"
  description = "Arbitrary prefix that can be used to disambiguate resources related to multiple instances of this configuration"
}

# Provisioning a GKE cluster for Istio and example services

provider "google" {
  credentials = "${file(var.gcp_credentials)}"
  project     = "${var.gcp_project}"
  region      = "us-central1"
  zone        = "us-central1-a"
}

resource "google_container_cluster" "primary" {
  name               = "${var.prefix}-tf-mx-primary"
  initial_node_count = 3

  # disable basic auth
  master_auth {
    username = ""
    password = ""
  }

  node_config {
    machine_type = "n1-standard-4"

    oauth_scopes = [
      "https://www.googleapis.com/auth/compute",
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
    ]
  }

  timeouts {
    create = "15m"
    update = "15m"
  }
}

data "google_client_config" "default" {}


# Kubernetes credentials for the GKE cluster and RBAC initialization

provider "kubernetes" {
  load_config_file = false

  host = "https://${google_container_cluster.primary.endpoint}"
  cluster_ca_certificate = "${base64decode(google_container_cluster.primary.master_auth.0.cluster_ca_certificate)}"
  token = "${data.google_client_config.default.access_token}"
}

resource "kubernetes_cluster_role_binding" "cluster_admin_binding" {
    metadata {
        name = "cluster-admin-binding-client"
    }
    role_ref {
        api_group = "rbac.authorization.k8s.io"
        kind = "ClusterRole"
        name = "cluster-admin"
    }
    subject {
        kind = "User"
        name = "client"
        api_group = "rbac.authorization.k8s.io"
    }
}

resource "local_file" "kubeconfig" {
  filename = "${path.module}/data/kubeconfig"
  sensitive_content = <<__EOF__
apiVersion: v1
kind: Config
preferences: {}
clusters:
- cluster:
    certificate-authority-data: ${google_container_cluster.primary.master_auth.0.cluster_ca_certificate}
    server: https://${google_container_cluster.primary.endpoint}
  name: primary
contexts:
- context:
    cluster: primary
    user: client
  name: primary
current-context: primary
users:
- name: client
  user:
    client-certificate-data: ${google_container_cluster.primary.master_auth.0.client_certificate}
    client-key-data: ${google_container_cluster.primary.master_auth.0.client_key}
__EOF__
}

# Installing Istio

resource "kubernetes_namespace" "istio_system" {
  metadata {
    name = "istio-system"
    annotations {
      istio.provisioner.build = "1.1.4"
      #istio.provisioner.build = "release-1.1-20190402-09-16"
      #istio.provisioner.build = "release-1.1-latest-daily"

      #istio.provisioner.options.global.mtls.enabled = "true"
      istio.provisioner.options.global.meshExpansion.enabled = "true"
      #istio.provisioner.options.global.controlPlaneSecurityEnabled = "false"
    }
  }
}

resource "null_resource" "istio_system" {
  triggers {
    istio_namespace_uid = "${kubernetes_namespace.istio_system.metadata.0.uid}"
    istio_provisioner_config = "${jsonencode(kubernetes_namespace.istio_system.metadata.0.annotations["istio"])}"
  }

  provisioner "local-exec" {
    command = "${path.module}/istio/provisioner -n ${kubernetes_namespace.istio_system.metadata.0.name} -cfg ${local_file.kubeconfig.filename} -ctx primary -o ${path.module}/data"
  }
}

# Enabling access to `kube-dns` service (that is not Istio-aware) from within the mesh.

resource "local_file" "kubedns_drule" {
  depends_on = [
    "kubernetes_namespace.istio_system",
    "null_resource.istio_system",
  ]

  filename = "${path.module}/data/kubedns_drule.yaml"

  content = <<__EOF__
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: kube-dns
  namespace: istio-system
spec:
  host: kube-dns.kube-system.svc.cluster.local
  trafficPolicy:
    tls:
      mode: DISABLE
__EOF__
}

resource "null_resource" "kubedns_drule" {
  provisioner "local-exec" {
    command = "kubectl --kubeconfig=${local_file.kubeconfig.filename} --context=primary apply -f ${local_file.kubedns_drule.filename}"
  }
}

# Setting up test service

resource "kubernetes_namespace" "internal" {
  depends_on = [
    "kubernetes_namespace.istio_system",
    "null_resource.istio_system",
  ]

  metadata {
    name = "internal"
    labels {
      istio-injection = "enabled"
    }
  }
}

resource "kubernetes_service" "test_service" {
  metadata {
    name = "test-service"
    namespace = "${kubernetes_namespace.internal.metadata.0.name}"
  }
  spec {
    selector {
      app = "test-service"
    }
    port {
      port = 8080
      name = "http-echo"
    }
  }
}

resource "kubernetes_deployment" "test_service" {
  depends_on = [
    "kubernetes_service.test_service"
  ]

  metadata {
    name = "test-service"
    namespace = "${kubernetes_namespace.internal.metadata.0.name}"
  }

  spec {
    selector {
      match_labels {
        app = "test-service"
      }
    }
    template {
      metadata {
        labels {
          app = "test-service"
        }
      }
      spec {
        container {
          image = "fortio/fortio"
          name = "test-service"
          port {
            container_port = "8080"
          }
          args = [
            "server",
          ]
        }
      }
    }
  }
}

# Extracting/creating Istio-related artifacts that need to be provisioned to the mesh expansion VMs

resource "local_file" "cluster_env" {
  filename = "${path.module}/data/cluster.env"
  content = <<__EOF__
ISTIO_CP_AUTH=MUTUAL_TLS
ISTIO_SERVICE_CIDR=${google_container_cluster.primary.cluster_ipv4_cidr}
__EOF__
}

resource "kubernetes_namespace" "external" {
  depends_on = ["null_resource.istio_system"]

  metadata {
    name = "external"
    labels {
      istio-injection = "enabled"
    }
  }

  provisioner "local-exec" {
    command = "until kubectl --kubeconfig=${local_file.kubeconfig.filename} --context=primary -n ${kubernetes_namespace.external.metadata.0.name} get secret istio.default; do sleep 3; done"
  }
  provisioner "local-exec" {
    command = "kubectl --kubeconfig=${local_file.kubeconfig.filename} --context=primary -n ${kubernetes_namespace.external.metadata.0.name} get secret istio.default -o jsonpath='{.data.root-cert\\.pem}' | base64 --decode > ${path.module}/data/root-cert.pem"
  }
  provisioner "local-exec" {
    command = "kubectl --kubeconfig=${local_file.kubeconfig.filename} --context=primary -n ${kubernetes_namespace.external.metadata.0.name} get secret istio.default -o jsonpath='{.data.key\\.pem}' | base64 --decode > ${path.module}/data/key.pem"
  }
  provisioner "local-exec" {
    command = "kubectl --kubeconfig=${local_file.kubeconfig.filename} --context=primary -n ${kubernetes_namespace.external.metadata.0.name} get secret istio.default -o jsonpath='{.data.cert-chain\\.pem}' | base64 --decode > ${path.module}/data/cert-chain.pem"
  }
}

# Creating a VM, setting up SSH access (used to transfer required artifacts and perform initialization)

resource "google_compute_firewall" "allow_ssh" {
  name = "${var.prefix}-allow-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["meshx-vm-instance"]
}

resource "tls_private_key" "meshx_vm_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "google_compute_instance" "meshx_vm_instance_1" {
  name         = "${var.prefix}-meshx-vm-instance-1"
  machine_type = "f1-micro"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-9"
    }
  }

  network_interface {
    network = "default"
    access_config {
    }
  }

  metadata {
    ssh-keys = "client:${tls_private_key.meshx_vm_key.public_key_openssh}"
  }

  # Backing up original hosts-file (allows for idempotency later on)
  provisioner "remote-exec" {
    inline = [ "sudo cp /etc/hosts hosts.orig" ]
    connection = {
      type = "ssh"
      user = "client"
      private_key = "${tls_private_key.meshx_vm_key.private_key_pem}"
      agent = "false"
    }
  }
  # Backing up original resolv.conf-file (allows for idempotency later on)
  provisioner "remote-exec" {
    inline = [ "sudo cp /etc/resolv.conf resolv.conf.orig" ]
    connection = {
      type = "ssh"
      user = "client"
      private_key = "${tls_private_key.meshx_vm_key.private_key_pem}"
      agent = "false"
    }
  }

  depends_on = ["google_compute_firewall.allow_ssh"]
  tags = ["meshx-vm-instance"]
}

# Configuring VM to enable communication between the services via Istio mesh

resource "null_resource" "meshx_vm_instance_1" {
  depends_on = [
    "kubernetes_namespace.external",
    "null_resource.istio_system",
    "null_resource.kubedns_drule",
    "google_compute_firewall.allow_ssh",
  ]

  triggers {
    cluster_env_content = "${local_file.cluster_env.content}"
    istio_provisioner_config = "${jsonencode(kubernetes_namespace.istio_system.metadata.0.annotations["istio"])}"
    mesh_vm_instance = "${google_compute_instance.meshx_vm_instance_1.instance_id}"
    ns_external = "${kubernetes_namespace.external.metadata.0.uid}"
  }

  connection = {
    host = "${google_compute_instance.meshx_vm_instance_1.network_interface.0.access_config.0.nat_ip}"
    type = "ssh"
    user = "client"
    private_key = "${tls_private_key.meshx_vm_key.private_key_pem}"
    agent = "false"
  }

  provisioner "file" {
    source      = "${local_file.cluster_env.filename}"
    destination = "/home/client/cluster.env"
  }
  provisioner "file" {
    source      = "${path.module}/data/hosts"
    destination = "/home/client/hosts"
  }
  provisioner "file" {
    source      = "${path.module}/data/resolv.conf"
    destination = "/home/client/resolv.conf"
  }
  provisioner "file" {
    source      = "${path.module}/data/istio-sidecar.deb"
    destination = "/home/client/istio-sidecar.deb"
  }
  provisioner "file" {
    source      = "${path.module}/data/root-cert.pem"
    destination = "/home/client/root-cert.pem"
  }
  provisioner "file" {
    source      = "${path.module}/data/key.pem"
    destination = "/home/client/key.pem"
  }
  provisioner "file" {
    source      = "${path.module}/data/cert-chain.pem"
    destination = "/home/client/cert-chain.pem"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo apt install -y dnsutils",
      "sudo dpkg -i istio-sidecar.deb",

      "cat hosts.orig | sudo tee /etc/hosts > /dev/null",
      "cat hosts | sudo tee -a /etc/hosts > /dev/null",

      "sudo mkdir -p /etc/certs",
      "sudo cp *.pem /etc/certs",
      "sudo chown -R istio-proxy /etc/certs",

      "sudo cp cluster.env /var/lib/istio/envoy",
      "sudo chown -R istio-proxy /var/lib/istio/envoy",

      "sudo systemctl start istio-auth-node-agent",
      "sudo systemctl start istio",

      "sudo cp resolv.conf /etc/resolv.conf",

      "until dig +tcp +short test-service.internal.svc.cluster.local; do sleep 3; done;",
      "curl --fail http://test-service.internal.svc.cluster.local:8080/debug",
      "echo \"[OK] verified connectivity: MESH EXPANSION VM -> ISTIO MESH\"",

      "nohup python -m SimpleHTTPServer 8080 </dev/null >http.log 2>&1 &",
      "sleep 3",
      "exit",
    ]
  }
}

# Adding a service running on a mesh expansion VM to the Istio mesh

resource "kubernetes_service" "vmhttp" {
  metadata {
    name = "vmhttp"
    namespace = "${kubernetes_namespace.external.metadata.0.name}"
  }
  spec {
    port {
      port = 8080
      protocol = "TCP"
    }
  }
}

resource "local_file" "vmhttp_serviceentry" {
  filename = "${path.module}/data/vmhttp_serviceentry.yaml"

  content = <<__EOF__
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: vmhttp
  namespace: ${kubernetes_namespace.external.metadata.0.name}
spec:
  hosts:
  - vmhttp.${kubernetes_namespace.external.metadata.0.name}.svc.cluster.local
  ports:
  - number: 8080
    name: http
    protocol: HTTP
  resolution: STATIC
  endpoints:
  - address: ${google_compute_instance.meshx_vm_instance_1.network_interface.0.network_ip}
    ports:
      http: 8080
    labels:
      app: vmhttp
      version: "v1"
__EOF__
}

resource "null_resource" "vmhttp_serviceentry" {
  depends_on = [
    "kubernetes_service.vmhttp",
    "null_resource.meshx_vm_instance_1",
    "kubernetes_deployment.test_service"
  ]

  triggers {
    vmhttp_serviceentry_file_change = "local_file.vmhttp_serviceentry.content"
  }

  provisioner "local-exec" {
    command = "kubectl --kubeconfig=${local_file.kubeconfig.filename} --context=primary apply -f ${local_file.vmhttp_serviceentry.filename}"
  }

  provisioner "local-exec" {
    command = <<__EOF__
POD=$$(kubectl --kubeconfig=${local_file.kubeconfig.filename} --context=primary -n internal get pods -l app=test-service -o jsonpath={.items[0].metadata.name})
kubectl --kubeconfig=${local_file.kubeconfig.filename} --context=primary -n internal exec -it $$POD -- fortio curl http://vmhttp.external.svc.cluster.local:8080/
echo "[OK] verified connectivity: ISTIO MESH -> MESH EXPANSION VM"
__EOF__
  }
}
