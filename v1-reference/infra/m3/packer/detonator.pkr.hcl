packer {
  required_plugins {
    googlecompute = { source = "github.com/hashicorp/googlecompute", version = ">= 1.1.6" }
  }
}

variable "project" { type = string }
variable "zone" { type = string }
variable "network" { type = string }
variable "fixture_apk" { type = string }
variable "bank_one_apk" { type = string }
variable "bank_two_apk" { type = string }

source "googlecompute" "m3_tools" {
  project_id              = var.project
  zone                    = var.zone
  source_image_family     = "ubuntu-2204-lts"
  source_image_project_id = ["ubuntu-os-cloud"]
  image_name              = "drishti-m3-tools-{{timestamp}}"
  image_family            = "drishti-m3-tools"
  machine_type            = "n2-standard-4"
  disk_size               = 80
  tags                    = ["drishti-builder"]
  network                 = var.network
  use_internal_ip         = false
  use_iap                 = true
  enable_nested_virtualization = true
  metadata = { block-project-ssh-keys = "true" }
}

build {
  sources = ["source.googlecompute.m3_tools"]
  provisioner "file" { source = var.fixture_apk destination = "/tmp/m3-inert-fixture.apk" }
  provisioner "file" { source = var.bank_one_apk destination = "/tmp/bank-one.apk" }
  provisioner "file" { source = var.bank_two_apk destination = "/tmp/bank-two.apk" }
  provisioner "file" { source = "${path.root}/../../../backend/drishti" destination = "/tmp/drishti" }
  provisioner "file" { source = "${path.root}/../../../backend/scripts/frida_hooks.js" destination = "/tmp/frida_hooks.js" }
  provisioner "file" { source = "${path.root}/../../../backend/scripts/dynamic_analyze.py" destination = "/tmp/dynamic_analyze.py" }
  provisioner "file" { source = "${path.root}/../../../backend/scripts/verify_containment.py" destination = "/tmp/verify_containment.py" }
  provisioner "file" { source = "${path.root}/../../../backend/scripts/emulator_control.sh" destination = "/tmp/emulator_control.sh" }
  provisioner "file" { source = "${path.root}/../runtime_lockdown.sh" destination = "/tmp/runtime_lockdown.sh" }
  provisioner "file" { source = "${path.root}/../runtime_prepare.sh" destination = "/tmp/runtime_prepare.sh" }
  provisioner "file" { source = "${path.root}/../fake_c2.py" destination = "/tmp/fake_c2.py" }
  provisioner "file" { source = "${path.root}/builder_setup.sh" destination = "/tmp/builder_setup.sh" }
  provisioner "shell" { inline = ["chmod +x /tmp/builder_setup.sh", "sudo /tmp/builder_setup.sh"] }
}
