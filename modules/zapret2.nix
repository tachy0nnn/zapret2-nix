# ============================================================================
# services.zapret2 — декларативная обвязка вокруг bol-van/zapret2.
#
# Отвечает ровно за одно (SRP): жизненный цикл nfqws2 — какие пресеты доступны,
# какой активен, как процесс запускается и переживает перезагрузку.
# Про firewall знает firewall.nix, про содержимое стратегий — presets/.
#
# Инверсия зависимостей: модуль НЕ импортирует конкретные пресеты. Он зависит
# от контракта (lib/types.nix) и получает пресеты через опции `presetLibrary`
# и `extraPresets`. Поэтому свой пресет можно подключить без форка проекта,
# а сам модуль пригоден к переносу в nixpkgs без нашей библиотеки.
#
# Модель «гибрид»:
#   • ЧТО ДОСТУПНО — декларативно: /etc/zapret2/available/<name>.conf (в store)
#   • ЧТО АКТИВНО  — runtime: симлинк /var/lib/zapret2/active.conf
# Переключение стратегии не требует пересборки системы: стратегии протухают
# быстро, и гонять `nixos-rebuild` на каждую пробу — неприемлемо больно.
# ============================================================================
{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    mkOption
    mkEnableOption
    mkPackageOption
    types
    mkIf
    ;

  cfg = config.services.zapret2;
  zLib = import ../lib { inherit lib pkgs; };

  # Библиотека + пользовательские пресеты. Пользовательские имеют приоритет,
  # то есть встроенный пресет можно переопределить своим, не трогая репозиторий.
  allPresets = cfg.presetLibrary // cfg.extraPresets;

  unknown = lib.subtractLists (lib.attrNames allPresets) cfg.presets;
  selected = map (n: allPresets.${n}) (lib.filter (n: allPresets ? ${n}) cfg.presets);

  confOf =
    preset:
    zLib.mkPresetConf {
      inherit preset;
      inherit (cfg) qnum;
      fwmark = cfg.firewall.desyncMark;
      luaInit = map (f: "${cfg.package}/share/zapret2/lua/${f}") cfg.luaModules;
    };

  availableDir = "/etc/zapret2/available";
  stateDir = "/var/lib/zapret2";
  activeLink = "${stateDir}/active.conf";

  # ---------------------------------------------------------------------------
  # CLI управления. Полноценный TUI с автоподбором — следующая версия, но без
  # какого-либо переключателя «гибридная» модель существует только на бумаге,
  # поэтому минимальный контроль входит уже сюда.
  # ---------------------------------------------------------------------------
  zapret2ctl = pkgs.writeShellApplication {
    name = "zapret2ctl";
    runtimeInputs = with pkgs; [
      systemd
      coreutils
    ];
    text = ''
      set -euo pipefail
      AVAILABLE="${availableDir}"
      ACTIVE="${activeLink}"

      # readlink БЕЗ -f, и это важно. Симлинк указывает на
      # /etc/zapret2/available/<имя>.conf, который сам ведёт в nix store.
      # `readlink -f` разрешает цепочку до конца и возвращает
      # /nix/store/<хеш>-zapret2-<имя>.conf — пользователю показывался хеш
      # вместо имени пресета, а в `list` из-за этого никогда не появлялась
      # звёздочка у активного. Один уровень — ровно то, что мы сами записали.
      current() {
        [ -L "$ACTIVE" ] || { echo "(не задан)"; return; }
        basename "$(readlink "$ACTIVE")" .conf
      }

      case "''${1-status}" in
        status)
          echo "Активный пресет : $(current)"
          echo -n "Служба          : "
          systemctl is-active zapret2 || true
          ;;
        list)
          for f in "$AVAILABLE"/*.conf; do
            [ -e "$f" ] || { echo "нет доступных пресетов"; exit 1; }
            n="$(basename "$f" .conf)"
            if [ "$n" = "$(current)" ]; then echo "* $n"; else echo "  $n"; fi
          done
          ;;
        switch)
          name="''${2-}"
          [ -n "$name" ] || { echo "укажи имя пресета: zapret2ctl switch <name>" >&2; exit 1; }
          [ -e "$AVAILABLE/$name.conf" ] || {
            echo "пресет '$name' не найден. Доступные:" >&2
            zapret2ctl list >&2
            exit 1
          }
          ln -sfn "$AVAILABLE/$name.conf" "$ACTIVE"
          systemctl restart zapret2
          echo "Активен: $name"
          ;;
        *)
          echo "zapret2ctl {status|list|switch <name>}" >&2
          exit 1
          ;;
      esac
    '';
  };
in
{
  imports = [ ./firewall.nix ];

  options.services.zapret2 = {
    enable = mkEnableOption "обход DPI через bol-van/zapret2 (nfqws2)";

    package = mkPackageOption pkgs "zapret2" { };

    presetLibrary = mkOption {
      type = types.attrsOf zLib.presetType;
      default = zLib.loadPresets ../presets;
      defaultText = lib.literalExpression "пресеты из каталога presets/ этого флейка";
      description = ''
        Библиотека доступных пресетов. Точка инверсии зависимостей: можно
        подменить целиком (например, на свой набор), не форкая модуль.
        Обычно её не трогают, а добавляют своё через `extraPresets`.
      '';
    };

    extraPresets = mkOption {
      type = types.attrsOf zLib.presetType;
      default = { };
      example = lib.literalExpression ''
        {
          my-isp = {
            description = "Стратегия под моего провайдера";
            hostlist = [ "example.com" ];
            profiles = [{
              filter = { tcp = "443"; l7 = [ "tls" ]; };
              payload = [ "tls_client_hello" ];
              desync = [ "fake:blob=fake_default_tls" "multisplit:pos=1" ];
            }];
          };
        }
      '';
      description = ''
        Свои пресеты. Проходят ту же валидацию, что и встроенные, и
        взаимозаменяемы с ними. Одноимённый пресет перекрывает библиотечный.
      '';
    };

    presets = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [
        "youtube"
        "discord"
      ];
      description = ''
        Какие пресеты сделать доступными в системе. Они попадут в
        `${availableDir}` и между ними можно будет переключаться
        через `zapret2ctl switch <name>` без пересборки.
      '';
    };

    defaultPreset = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "youtube";
      description = ''
        Пресет, который становится активным при первом запуске (и если
        текущий активный исчез из конфигурации). По умолчанию — первый из
        `presets`.
      '';
    };

    luaModules = mkOption {
      type = types.listOf types.str;
      default = [
        "zapret-lib.lua"
        "zapret-antidpi.lua"
        "zapret-auto.lua"
      ];
      example = [
        "zapret-lib.lua"
        "zapret-antidpi.lua"
        "zapret-auto.lua"
        "zapret-obfs.lua"
      ];
      description = ''
        Lua-файлы из пакета zapret2, загружаемые перед стратегиями
        (`--lua-init`). Именно они определяют функции воздействий: `fake`,
        `multisplit`, `multidisorder` и прочие — в самом бинаре их нет.
        Порядок важен: `zapret-lib` идёт первым, остальные строятся на нём.

        Набор по умолчанию повторяет апстримные init-скрипты. Добавляй сюда,
        если пресету нужны функции из других модулей (например `zapret-obfs`).
      '';
    };

    qnum = mkOption {
      type = types.int;
      default = 200;
      description = ''
        Номер очереди NFQUEUE. Менять нужно только при конфликте с другим
        софтом, который тоже пользуется netfilter_queue.
      '';
    };

    firewall = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Настраивать правила заворачивания трафика в NFQUEUE.
          Выключи, если правишь firewall сам.
        '';
      };

      backend = mkOption {
        type = types.enum [
          "auto"
          "nftables"
          "iptables"
        ];
        default = "auto";
        description = ''
          Чем настраивать правила. `auto` — nftables, если включён
          `networking.nftables.enable`, иначе iptables.
        '';
      };

      ports = {
        tcp = mkOption {
          type = types.nullOr (types.listOf types.str);
          default = null;
          example = [
            "80"
            "443"
          ];
          description = ''
            TCP-порты для перехвата. По умолчанию (`null`) выводятся из
            фильтров выбранных пресетов — так не бывает рассинхрона между
            «что чинит пресет» и «что заворачивается в очередь».
            Указывать вручную нужно, только если пресет использует `*` или `~`.
          '';
        };
        udp = mkOption {
          type = types.nullOr (types.listOf types.str);
          default = null;
          example = [
            "443"
            "50000-65535"
          ];
          description = "UDP-порты для перехвата. Логика та же, что у tcp.";
        };
      };

      connbytesLimit = mkOption {
        type = types.int;
        default = 6;
        description = ''
          Сколько первых пакетов соединения отдавать в nfqws2. Большинству
          DPI хватает начала сессии, а нагрузка на CPU кратно ниже.
          `0` — обрабатывать все пакеты (нужно, если DPI смотрит сессию целиком).
        '';
      };

      desyncMark = mkOption {
        type = types.str;
        default = "0x40000000";
        description = ''
          Метка, которой nfqws2 помечает свои пакеты, чтобы они не попали
          в очередь повторно. Совпадает с DESYNC_MARK апстрима.
        '';
      };
    };

    # Внутренний контракт между модулями: firewall.nix берёт отсюда пресеты,
    # чтобы вывести порты. Не часть публичного API.
    _resolvedPresets = mkOption {
      type = types.listOf types.attrs;
      internal = true;
      readOnly = true;
      default = selected;
      description = "Разрешённые пресеты (внутреннее).";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.presets != [ ];
        message = ''
          services.zapret2.presets пуст — нечего запускать.
          Выбери хотя бы один пресет, например: presets = [ "general" ];
          Доступные: ${lib.concatStringsSep ", " (lib.attrNames allPresets)}
        '';
      }
      {
        assertion = unknown == [ ];
        message = ''
          services.zapret2.presets содержит неизвестные пресеты: ${lib.concatStringsSep ", " unknown}
          Доступные: ${lib.concatStringsSep ", " (lib.attrNames allPresets)}
          Свой пресет можно добавить через services.zapret2.extraPresets.
        '';
      }
      {
        assertion = cfg.defaultPreset == null || lib.elem cfg.defaultPreset cfg.presets;
        message = ''
          services.zapret2.defaultPreset = "${toString cfg.defaultPreset}" отсутствует
          в services.zapret2.presets = [ ${lib.concatStringsSep " " cfg.presets} ].
        '';
      }
      {
        assertion = lib.all (p: p.profiles != [ ]) selected;
        message = "services.zapret2: пресет без профилей ничего не делает — проверь presets/extraPresets.";
      }
    ];

    # Каталог доступных пресетов — декларативная часть SSOT.
    environment.etc = lib.mkMerge (
      map (p: {
        "zapret2/available/${p.name}.conf".source = confOf p;
      }) selected
    );

    environment.systemPackages = [
      zapret2ctl
      cfg.package # blockcheck2 под рукой для ручного подбора
    ];

    systemd.services.zapret2 = {
      description = "DPI bypass (zapret2 / nfqws2)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        # Пакет собран с libsystemd, nfqws2 умеет sd_notify — ждём готовности
        # честно, а не гадаем по таймеру.
        Type = "notify";
        Restart = "on-failure";
        RestartSec = "5s";

        StateDirectory = "zapret2";
        # 0755, а не 0700: внутри лежит единственный симлинк на активный пресет,
        # и ничего секретного в нём нет — сами пресеты и так публичны в
        # /etc/zapret2/available. При 0700 обычный пользователь не мог войти в
        # каталог, и `zapret2ctl status` без sudo врал «(не задан)», хотя
        # пресет был выставлен. Запись остаётся только у root.
        StateDirectoryMode = "0755";

        # `@file` должен быть единственным аргументом nfqws2 — все опции,
        # включая --qnum, лежат внутри самого файла.
        ExecStart = "${cfg.package}/bin/nfqws2 @${activeLink}";

        # Хардненинг — база из апстримного nfqws2@.service.
        RestrictAddressFamilies = "AF_NETLINK AF_UNIX AF_INET AF_INET6";
        CapabilityBoundingSet = "CAP_NET_ADMIN CAP_NET_RAW CAP_SETPCAP";
        LockPersonality = true;
        # MemoryDenyWriteExecute НЕ включаем: стратегии zapret2 исполняются
        # LuaJIT, которому нужна W+X-память под джит-код. С этим флагом
        # nfqws2 падает при загрузке первой же Lua-стратегии.
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateMounts = true;
        PrivateTmp = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RemoveIPC = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        UMask = "0077";
      };

      # Активный пресет мог исчезнуть из конфигурации после пересборки —
      # тогда симлинк повиснет и служба не поднимется. Чиним до старта.
      preStart =
        let
          fallback = if cfg.defaultPreset != null then cfg.defaultPreset else builtins.head cfg.presets;
        in
        ''
          if [ ! -e "${activeLink}" ]; then
            ln -sfn "${availableDir}/${fallback}.conf" "${activeLink}"
          fi
        '';
    };
  };
}
