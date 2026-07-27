# zapret2-nix

Declarative NixOS module and preset library for
[bol-van/zapret2](https://github.com/bol-van/zapret2) — DPI bypass without
third-party servers.

*[Русская версия](README.ru.md)*

> **Status: v0.1.** The module and presets work. The interactive TUI with
> automatic strategy discovery is planned for v0.2 — for now, `blockcheck2`
> (shipped with the `zapret2` package) and `zapret2ctl` cover the workflow.

## Why this exists

`nixpkgs` already ships the `zapret2` package, but there is **no NixOS module
for it** — only `services.zapret`, which targets the first generation and
[explicitly refuses to configure nftables](https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/networking/zapret.nix).
So on NixOS you are left wiring systemd units and firewall rules by hand.

This project fills that gap:

- **`services.zapret2`** — declarative service, both **nftables and iptables**
- **Preset library** — ready-made strategies instead of hand-crafted flag soup
- **Runtime switching** — change strategy without a rebuild; bypass strategies
  rot quickly, and `nixos-rebuild` on every attempt is painful

## Quick start

```nix
# flake.nix
{
  inputs.zapret2-nix.url = "github:ZenonEl/zapret2-nix";

  outputs = { nixpkgs, zapret2-nix, ... }: {
    nixosConfigurations.mymachine = nixpkgs.lib.nixosSystem {
      modules = [
        zapret2-nix.nixosModules.default
        {
          services.zapret2 = {
            enable = true;
            presets = [ "youtube" "discord" ];
            defaultPreset = "youtube";
          };
        }
      ];
    };
  };
}
```

After a rebuild:

```console
$ zapret2ctl status
Активный пресет : youtube
Служба          : active

$ zapret2ctl list
* youtube
  discord

$ sudo zapret2ctl switch discord     # no rebuild needed
Активен: discord
```

## How it works

The module separates **what is available** from **what is active**:

| | Where | Managed by |
|---|---|---|
| Available presets | `/etc/zapret2/available/*.conf` (Nix store) | declarative, your config |
| Active preset | `/var/lib/zapret2/active.conf` (symlink) | runtime, `zapret2ctl` |

`nfqws2` runs as a systemd service reading the active symlink. Firewall rules
send matching traffic to NFQUEUE — and the ports are **derived from the presets
themselves**, so the rules can never drift out of sync with the strategies.

## Presets

| Preset | What it covers |
|---|---|
| `youtube` | YouTube / googlevideo — TLS ClientHello + QUIC |
| `discord` | Discord — TLS for API/CDN, STUN + IP discovery for voice |
| `general` | Generic HTTP + TLS + QUIC, no domain restriction |

No preset works everywhere: DPI differs between ISPs and changes over time. If
none of them work, find your own strategy with `blockcheck2` (see below) and
either add it locally via `extraPresets` or
[contribute it](CONTRIBUTING.md).

### Finding a working strategy

```console
$ sudo blockcheck2
```

`blockcheck2` ships with the `zapret2` package and tests strategies against
real blocked sites on **your** connection. Translate what it finds into a
preset:

```nix
services.zapret2.extraPresets.my-isp = {
  description = "Strategy for my ISP";
  hostlist = [ "example.com" ];
  profiles = [{
    filter = { tcp = "443"; l7 = [ "tls" ]; };
    payload = [ "tls_client_hello" ];
    desync = [ "fake:blob=fake_default_tls" "multisplit:pos=1" ];
  }];
};
```

Your presets go through the same validation as the built-in ones and are fully
interchangeable with them. Same-named presets override the built-ins — you
never need to fork this repository.

## Options

| Option | Default | Description |
|---|---|---|
| `enable` | `false` | Enable the service |
| `presets` | `[ ]` | Which presets to make available |
| `defaultPreset` | first of `presets` | Active on first boot |
| `extraPresets` | `{ }` | Your own presets |
| `presetLibrary` | built-in | Replace the whole library (dependency injection) |
| `qnum` | `200` | NFQUEUE number |
| `firewall.enable` | `true` | Configure firewall rules |
| `firewall.backend` | `"auto"` | `auto` / `nftables` / `iptables` |
| `firewall.ports.{tcp,udp}` | `null` (derive from presets) | Override port detection |
| `firewall.connbytesLimit` | `6` | First N packets per connection; `0` = all |

Full descriptions are in the option docs (`modules/zapret2.nix`).

## Legal notice

DPI bypass may be regulated where you live. This is a packaging project: it
installs and configures upstream software, and makes no claim about the
legality of using it in your jurisdiction. You are responsible for how you use
it.

## Credits

- [bol-van/zapret2](https://github.com/bol-van/zapret2) — the engine and the
  Lua strategies everything here builds on
- [Snowy-Fluffy/zapret.installer](https://github.com/Snowy-Fluffy/zapret.installer) —
  the "pick a preset and it just works" idea, for the first generation

## License

[GPL-3.0-or-later](LICENSE).
