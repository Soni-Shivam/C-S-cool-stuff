provider "google" { project = var.project }

resource "google_compute_firewall" "iap_ssh" {
  name          = "drishti-detonator-iap-ssh"
  network       = var.network
  direction     = "INGRESS"
  priority      = 100
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["detonator"]
  allow { protocol = "tcp" ports = ["22"] }
}

resource "google_compute_firewall" "deny_runtime_egress" {
  name               = "drishti-detonator-deny-egress"
  network            = var.network
  direction          = "EGRESS"
  priority           = 100
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["detonator"]
  deny { protocol = "all" }
}

resource "google_compute_instance" "runtime" {
  name                      = var.instance_name
  zone                      = var.zone
  machine_type              = "n2-standard-4"
  allow_stopping_for_update = true
  tags                      = ["detonator"]
  deletion_protection       = false

  advanced_machine_features { enable_nested_virtualization = true }
  boot_disk {
    auto_delete = true
    initialize_params { image = var.runtime_image size = 80 type = "pd-balanced" }
  }
  network_interface {
    network    = var.network
    subnetwork = var.subnetwork
    # Deliberately no access_config: no external IP.
  }
  # Deliberately no service_account block: the runtime has no Google identity.
  metadata = {
    block-project-ssh-keys = "true"
    enable-oslogin         = "TRUE"
    disable-legacy-endpoints = "true"
    drishti-runtime-image    = var.runtime_image
  }
  metadata_startup_script = file("${path.module}/../../runtime_prepare.sh")
  scheduling {
    automatic_restart   = false
    on_host_maintenance = "TERMINATE"
  }
  depends_on = [google_compute_firewall.iap_ssh, google_compute_firewall.deny_runtime_egress]
}

output "runtime_internal_ip" { value = google_compute_instance.runtime.network_interface[0].network_ip }
output "runtime_has_external_ip" { value = length(google_compute_instance.runtime.network_interface[0].access_config) > 0 }
