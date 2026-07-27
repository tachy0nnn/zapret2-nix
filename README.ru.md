# zapret2-nix

Декларативный NixOS-модуль и библиотека пресетов для
[bol-van/zapret2](https://github.com/bol-van/zapret2) — обхода DPI без
сторонних серверов.

*[English version](README.md)*

> **Статус: v0.1.** Модуль и пресеты работают. Интерактивный TUI с
> автоподбором стратегии — в планах на v0.2; пока задачу закрывают
> `blockcheck2` (идёт в пакете `zapret2`) и `zapret2ctl`.

## Зачем это нужно

Пакет `zapret2` в `nixpkgs` уже есть, а вот **модуля к нему нет** — только
`services.zapret` под первое поколение, который к тому же
[прямо отказывается настраивать nftables](https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/networking/zapret.nix).
То есть на NixOS остаётся руками писать юниты и правила файрвола.

Проект закрывает эту дыру:

- **`services.zapret2`** — декларативный сервис, **и nftables, и iptables**
- **Библиотека пресетов** — готовые стратегии вместо самостоятельного
  подбора простыни флагов
- **Переключение на лету** — сменить стратегию без пересборки системы:
  стратегии протухают быстро, и гонять `nixos-rebuild` на каждую пробу больно

## Быстрый старт

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

После пересборки:

```console
$ zapret2ctl status
Активный пресет : youtube
Служба          : active

$ zapret2ctl list
* youtube
  discord

$ sudo zapret2ctl switch discord     # пересборка не нужна
Активен: discord
```

## Как устроено

Модуль разделяет **что доступно** и **что активно**:

| | Где | Кто управляет |
|---|---|---|
| Доступные пресеты | `/etc/zapret2/available/*.conf` (nix store) | декларативно, твой конфиг |
| Активный пресет | `/var/lib/zapret2/active.conf` (симлинк) | runtime, `zapret2ctl` |

`nfqws2` работает systemd-сервисом и читает активный симлинк. Правила файрвола
заворачивают подходящий трафик в NFQUEUE, причём **порты выводятся из самих
пресетов** — рассинхрон «пресет чинит одно, в очередь уходит другое»
невозможен by design.

## Пресеты

| Пресет | Что закрывает |
|---|---|
| `youtube` | YouTube / googlevideo — TLS ClientHello + QUIC |
| `discord` | Discord — TLS для API/CDN, STUN и IP discovery для голоса |
| `general` | Универсальный HTTP + TLS + QUIC, без привязки к доменам |

Универсального пресета не существует: DPI у провайдеров разный и меняется со
временем. Если ни один не подошёл — найди свою стратегию через `blockcheck2`
(ниже) и либо добавь её локально через `extraPresets`, либо
[пришли в проект](CONTRIBUTING.md).

### Как найти рабочую стратегию

```console
$ sudo blockcheck2
```

`blockcheck2` идёт в пакете `zapret2` и перебирает стратегии против реально
заблокированных сайтов на **твоём** канале. Найденное переносится в пресет:

```nix
services.zapret2.extraPresets.my-isp = {
  description = "Стратегия под моего провайдера";
  hostlist = [ "example.com" ];
  profiles = [{
    filter = { tcp = "443"; l7 = [ "tls" ]; };
    payload = [ "tls_client_hello" ];
    desync = [ "fake:blob=fake_default_tls" "multisplit:pos=1" ];
  }];
};
```

Свои пресеты проходят ту же валидацию, что и встроенные, и полностью с ними
взаимозаменяемы. Одноимённый пресет перекрывает библиотечный — форкать
репозиторий, чтобы что-то поправить под себя, не нужно.

## Опции

| Опция | По умолчанию | Описание |
|---|---|---|
| `enable` | `false` | Включить сервис |
| `presets` | `[ ]` | Какие пресеты сделать доступными |
| `defaultPreset` | первый из `presets` | Активен при первом запуске |
| `extraPresets` | `{ }` | Свои пресеты |
| `presetLibrary` | встроенная | Подменить библиотеку целиком (инверсия зависимостей) |
| `qnum` | `200` | Номер очереди NFQUEUE |
| `firewall.enable` | `true` | Настраивать правила файрвола |
| `firewall.backend` | `"auto"` | `auto` / `nftables` / `iptables` |
| `firewall.ports.{tcp,udp}` | `null` (вывести из пресетов) | Переопределить порты |
| `firewall.connbytesLimit` | `6` | Сколько первых пакетов соединения обрабатывать; `0` = все |

Подробные описания — в самих опциях (`modules/zapret2.nix`).

## Правовая оговорка

Обход DPI может быть предметом регулирования в твоей стране. Это проект по
упаковке: он ставит и настраивает чужое ПО и не делает никаких утверждений о
законности его применения в конкретной юрисдикции. Ответственность за
использование — на пользователе.

## Благодарности

- [bol-van/zapret2](https://github.com/bol-van/zapret2) — движок и Lua-стратегии,
  на которых всё держится
- [Snowy-Fluffy/zapret.installer](https://github.com/Snowy-Fluffy/zapret.installer) —
  идея «выбрал пресет и работает», для первого поколения

## Лицензия

[GPL-3.0-or-later](LICENSE).
