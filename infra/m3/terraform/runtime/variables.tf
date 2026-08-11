variable "project" { type = string }
variable "zone" { type = string }
variable "network" { type = string }
variable "subnetwork" { type = string }
variable "runtime_image" { type = string }
variable "instance_name" {
  type    = string
  default = "drishti-detonator"
}
