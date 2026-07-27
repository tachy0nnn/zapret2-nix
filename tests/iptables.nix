{ pkgs, self }:
import ./vm-common.nix {
  inherit pkgs self;
  backend = "iptables";
}
