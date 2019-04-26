variable "gcp_project" {
  type    = "string"
  default = "istio-test-230101"
}
variable "gcp_api_key_path" {
  type    = "string"
  default = "~/account.json"
}
variable "prefix" {
  type    = "string"
  default = "test"
}


provider "google" {
  credentials = "${file(var.gcp_api_key_path)}"
  project     = "${var.gcp_project}"
  region      = "us-central1"
  zone        = "us-central1-a"
}

resource "google_container_cluster" "primary" {
  name               = "${var.prefix}-tf-exp-primary"
  initial_node_count = 4

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


############################

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


##################

resource "kubernetes_namespace" "istio_system" {
  metadata {
    name = "istio-system"
    annotations {
      istio.provisioner.build = "1.1.2"
      #istio.provisioner.build = "release-1.1-20190402-09-16"
      #istio.provisioner.build = "release-1.1-latest-daily"

      #istio.provisioner.options.global.mtls.enabled = "true"
      istio.provisioner.options.global.meshExpansion.enabled = "true"
      #istio.provisioner.options.global.controlPlaneSecurityEnabled = "false"
      #istio.provisioner.options.global.sds.enabled = "true"
      #istio.provisioner.options.global.sds.udsPath = "unix:/var/run/sds/uds_path"
      #istio.provisioner.options.global.sds.useNormalJwt = "true"
      #istio.provisioner.options.nodeagent.enabled = "true"
      #istio.provisioner.options.nodeagent.image = "node-agent-k8s"
      #istio.provisioner.options.nodeagent.env.CA_PROVIDER = "Citadel"
      #istio.provisioner.options.nodeagent.env.CA_ADDR = "istio-citadel:8060"
      #istio.provisioner.options.nodeagent.env.VALID_TOKEN = "true"
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


###########


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

  provisioner "remote-exec" {
    inline = [ "sudo cp /etc/hosts hosts.orig" ]
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

resource "null_resource" "meshx_vm_instance_1" {
  depends_on = [
    "kubernetes_namespace.external",
    "null_resource.istio_system",
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
    ]
  }
}
