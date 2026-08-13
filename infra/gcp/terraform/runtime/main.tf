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
    # auto_delete = FALSE, deliberately. v1 had this `true`, which is why the only
    # copy of 14 real detonation artifacts sat one `instances delete` away from
    # non-existence in a project with zero buckets and zero snapshots. Deleting the VM
    # must not delete the evidence. See PROGRESS.md 2026-08-14.
    auto_delete = false
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

# A scheduled snapshot policy so evidence survives even an operator deleting the disk.
# The rescue proved that relying on "we will remember to copy it off" does not hold.
resource "google_compute_resource_policy" "runtime_snapshots" {
  name   = "${var.instance_name}-daily-snapshots"
  region = var.region
  snapshot_schedule_policy {
    schedule {
      daily_schedule {
        days_in_cycle = 1
        start_time    = "19:00"
      }
    }
    retention_policy {
      max_retention_days    = 14
      on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"
    }
  }
}

output "runtime_internal_ip" { value = google_compute_instance.runtime.network_interface[0].network_ip }
output "runtime_has_external_ip" { value = length(google_compute_instance.runtime.network_interface[0].access_config) > 0 }
