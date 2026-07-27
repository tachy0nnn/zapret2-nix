{
  description = "Декларативный NixOS-модуль и библиотека пресетов для zapret2 (обход DPI)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      # ----------------------------------------------------------------------
      # Модуль. Импортируется в конфигурацию системы:
      #   imports = [ zapret2-nix.nixosModules.default ];
      # ----------------------------------------------------------------------
      nixosModules = rec {
        zapret2 = ./modules/zapret2.nix;
        default = zapret2;
      };

      # ----------------------------------------------------------------------
      # Библиотека: контракт пресета и рендер. Вынесена наружу, чтобы её можно
      # было переиспользовать в своём модуле или тестах, не завися от нашего.
      # ----------------------------------------------------------------------
      lib = forAllSystems (
        pkgs:
        import ./lib {
          inherit (pkgs) lib;
          inherit pkgs;
        }
      );

      # Пресеты как данные — доступны отдельно от модуля.
      presets = import ./presets { lib = nixpkgs.lib; };

      checks = forAllSystems (
        pkgs:
        {
          # Контракт пресетов: каждый библиотечный пресет обязан проходить
          # валидацию типом и рендериться в непустой конфиг.
          presets-eval = import ./tests/presets-eval.nix { inherit pkgs; };
        }
        // nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          # Полный прогон в виртуалке: служба поднимается, правила встают и
          # снимаются, переключение пресета работает без пересборки.
          nftables = import ./tests/nftables.nix { inherit pkgs self; };
          iptables = import ./tests/iptables.nix { inherit pkgs self; };
        }
      );

      formatter = forAllSystems (pkgs: pkgs.nixfmt-tree);
    };
}
