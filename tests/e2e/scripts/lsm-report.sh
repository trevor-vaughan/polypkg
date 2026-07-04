#!/bin/sh
# Report the host's LSM enforcement state so a permissive run is never mistaken
# for an enforcing one. Container tests validate userland universality always;
# real SELinux/AppArmor enforcement depends on the host having it enabled.
set -eu
podman info --format \
  'LSM: selinux={{.Host.Security.SELinuxEnabled}} apparmor={{.Host.Security.AppArmorEnabled}} rootless={{.Host.Security.Rootless}}'
