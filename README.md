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
| `general-ts` | Same coverage, **different strategy family**: single `fake` with timestamp fooling, no split |

No preset works everywhere: DPI differs between ISPs and changes over time.

Mind the difference between a *preset* and a *strategy*. `youtube`, `discord` and
`general` differ only in **domain coverage** — the desync chain is the same in
all three: `fake` with `tcp_md5` plus `multisplit`/`multidisorder`. If your ISP's
DPI defeats that family, cycling through those three proves nothing: they break
identically. What you need is a different family, which is what `general-ts` is
(the zapret 1.x classic: `fake` with timestamp fooling and no request splitting).
If that doesn't work either, find your own with `zapret2-blockcheck` and either
add it locally via `extraPresets` or [contribute it](CONTRIBUTING.md).

### Finding a working strategy

```console
$ sudo zapret2-blockcheck --presets     # do my declared strategies work? (seconds)
$ sudo zapret2-blockcheck               # quick sweep of standard ones (minutes)
$ sudo zapret2-blockcheck --full        # full upstream sweep (hours)
```

`zapret2-blockcheck` wraps upstream `blockcheck2` and fixes three things about
it:

- **Time.** Upstream's standard scan spends ~85% of its probes on a TTL sweep,
  and every probe means starting `nfqws2`, installing rules and waiting for a
  curl timeout — hence hours. The quick mode drops the TTL sweep; bring it back
  with `--full` or `MAX_TTL=12`.
- **Your own strategies.** `--presets` tests **only** the chains from your
  declared presets. They are emitted to `/etc/zapret2/blockcheck/*.txt` from the
  same data as the running config, so the two cannot drift apart. This answers
  "are my presets wrong, or is the problem elsewhere?".
- **False success.** `blockcheck2` starts its own `nfqws2` and its own rules, so
  a running service means traffic is processed twice. And over a VPN, blocked
  sites open by themselves — every strategy is reported working, including an
  empty one. The service is stopped for the duration, and a tunnel aborts the
  run.

Translate what it finds into a preset:

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
| `firewall.interfaces` | `null` (all) | Outbound interfaces whose traffic is queued |
| `firewall.ports.{tcp,udp}` | `null` (derive from presets) | Override port detection |
| `firewall.connbytesLimit` | `6` | First N packets per connection; `0` = all |

Full descriptions are in the option docs (`modules/zapret2.nix`).

### With a VPN or Docker on the machine, set `firewall.interfaces`

```nix
services.zapret2.firewall.interfaces = [ "enp5s0" ]; # WAN only
```

The rule hooks postrouting, and without this option "all interfaces" means
literally all of them. A full tunnel (`tun0`, `wg0`, `amn0`…) takes over the
default route, and packets headed into it pass postrouting **before**
encapsulation — so `nfqws2` desyncs traffic *inside* the tunnel. Your ISP's DPI
can't see it there anyway, but the server on the far end does receive the forged
packets, so sessions break and any "is the bypass working?" test becomes
meaningless. Container traffic on 443 is queued for the same reason. Upstream
zapret 1.x narrows its rules to auto-detected WAN interfaces; here it is an
explicit list.

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
