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

  # Стратегии выбранных пресетов в формате списков blockcheck2 — по одному
  # файлу на вид теста. Нужны режиму `zapret2-blockcheck --presets`.
  candidateKinds = [
    "http"
    "tls"
    "quic"
  ];
  candidateFile = lib.genAttrs candidateKinds (kind: zLib.mkCandidateFile kind selected);
  candidateHas = kind: zLib.candidateLines kind selected != [ ];
  # Лежат в /etc, а не только в store: по ним видно, что именно будет
  # проверяться, и это тот же самый файл, который читает blockcheck2.
  candidateDir = "/etc/zapret2/blockcheck";

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

  # ---------------------------------------------------------------------------
  # Обвязка над апстримным blockcheck2 — подбором стратегии.
  #
  # Существует по трём причинам, каждая из которых иначе стоит либо часов, либо
  # ложного результата:
  #
  #  1. ВРЕМЯ. `standard`-скан апстрима перебирает на каждый протокол каждого
  #     домена ~200 стратегий, из которых ~170 — развёртка по TTL
  #     (MIN_TTL..MAX_TTL и autottl-дельты), и каждая стратегия это поднять
  #     nfqws2, поставить правила, дождаться таймаута curl. Отсюда «дико
  #     долго»: часы. Быстрый режим убирает развёртку по TTL и лишние
  #     протоколы — остаются десятки проверок, то есть минуты. TTL-семейство
  #     не потеряно: `--full` его вернёт.
  #
  #  2. ЧЕСТНОСТЬ РЕЗУЛЬТАТА. blockcheck2 поднимает СВОЙ nfqws2 на своей
  #     очереди и свои правила. Если наш zapret2 в это время работает, трафик
  #     обрабатывается дважды и результат ничего не значит. Апстрим лишь пишет
  #     об этом строчкой в вывод — здесь служба останавливается и возвращается
  #     обратно по выходу.
  #
  #  3. VPN. Через туннель заблокированное открывается само, и blockcheck2
  #     объявит рабочей ЛЮБУЮ стратегию, включая пустую. Это самый дорогой вид
  #     ошибки: он выглядит как успех. Проверяется до запуска.
  # ---------------------------------------------------------------------------
  zapret2-blockcheck = pkgs.writeShellApplication {
    name = "zapret2-blockcheck";
    runtimeInputs = with pkgs; [
      systemd
      iproute2
      coreutils
      gnugrep
      gawk
      cfg.package
    ];
    text = ''
      usage() {
        cat <<'EOF'
      zapret2-blockcheck [--presets|--fast|--full] [домен ...]

        --fast     (по умолчанию) стандартный перебор без развёртки по TTL,
                   только IPv4, TLS 1.2 и QUIC. Минуты вместо часов.
        --presets  проверить ТОЛЬКО стратегии из своих пресетов. Секунды.
                   Отвечает на вопрос «работает ли то, что я объявил».
        --full     апстримный blockcheck2 как есть, интерактивно и целиком.
                   Когда быстрый скан ничего не нашёл.

      Домены через пробел; по умолчанию берётся домен из апстрима.
      Любую переменную blockcheck2 можно переопределить из окружения:
        DOMAINS, IPVS, SCANLEVEL, REPEATS, CURL_MAX_TIME, MAX_TTL,
        ENABLE_HTTP, ENABLE_HTTPS_TLS12, ENABLE_HTTPS_TLS13, ENABLE_HTTP3.

      Служба zapret2 останавливается на время проверки и поднимается обратно.
      EOF
      }

      mode=fast
      case "''${1-}" in
        --presets) mode=presets; shift ;;
        --fast) mode=fast; shift ;;
        --full) mode=full; shift ;;
        -h | --help) usage; exit 0 ;;
        --*) echo "неизвестный ключ: $1" >&2; usage >&2; exit 1 ;;
      esac

      if [ "$(id -u)" != 0 ]; then
        echo "нужен root: sudo zapret2-blockcheck ''${mode:+--$mode}" >&2
        exit 1
      fi

      # --- туннель -----------------------------------------------------------
      # Полный туннель обычно ставит либо default через tun-подобный интерфейс,
      # либо пару 0.0.0.0/1 + 128.0.0.0/1 в обход default (так делает Amnezia).
      tunnel=""
      for r in "0.0.0.0/1" "default"; do
        for dev in $(ip -4 -o route show "$r" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}'); do
          case "$dev" in
            tun* | tap* | wg* | amn* | proton* | nordlynx | tailscale* | ppp*) tunnel="$dev" ;;
          esac
        done
      done
      if [ -n "$tunnel" ] && [ "''${ALLOW_VPN-}" != 1 ]; then
        cat >&2 <<EOF
      Поднят туннель ($tunnel) — проверка бессмысленна.
      Через VPN заблокированное открывается само, и blockcheck2 объявит рабочей
      любую стратегию, включая пустую. Результат будет выглядеть как успех.

      Выключи VPN и запусти снова. Если это не туннель, а ложное срабатывание:
      ALLOW_VPN=1 sudo zapret2-blockcheck ...
      EOF
        exit 1
      fi

      # --- своя служба -------------------------------------------------------
      restore=0
      if systemctl is-active --quiet zapret2.service; then
        echo "* останавливаю zapret2.service на время проверки"
        systemctl stop zapret2.service
        restore=1
      fi
      cleanup() {
        if [ "$restore" = 1 ]; then
          echo "* поднимаю zapret2.service обратно"
          systemctl start zapret2.service || true
        fi
      }
      trap cleanup EXIT INT TERM

      if [ "$#" -gt 0 ]; then
        DOMAINS="$*"
        export DOMAINS
      fi

      if [ "$mode" = full ]; then
        echo "* полный апстримный blockcheck2 (это надолго)"
        exec blockcheck2
      fi

      export BATCH=1
      export IPVS="''${IPVS:-4}"
      export REPEATS="''${REPEATS:-1}"
      export CURL_MAX_TIME="''${CURL_MAX_TIME:-2}"

      if [ "$mode" = presets ]; then
        export TEST=custom
        export LIST_HTTP="${candidateDir}/http.txt"
        export LIST_HTTPS_TLS12="${candidateDir}/tls.txt"
        export LIST_HTTPS_TLS13="${candidateDir}/tls.txt"
        export LIST_QUIC="${candidateDir}/quic.txt"
        export ENABLE_HTTP="''${ENABLE_HTTP:-${if candidateHas "http" then "1" else "0"}}"
        export ENABLE_HTTPS_TLS12="''${ENABLE_HTTPS_TLS12:-${if candidateHas "tls" then "1" else "0"}}"
        export ENABLE_HTTPS_TLS13="''${ENABLE_HTTPS_TLS13:-0}"
        export ENABLE_HTTP3="''${ENABLE_HTTP3:-${if candidateHas "quic" then "1" else "0"}}"
        echo "* проверяю стратегии своих пресетов: ${lib.concatMapStringsSep ", " (p: p.name) selected}"
      else
        export TEST="''${TEST:-standard}"
        export SCANLEVEL="''${SCANLEVEL:-quick}"
        # Развёртка по TTL — это ~85% всех проверок стандартного скана.
        # Отключаем в быстром режиме; вернуть — MAX_TTL=12 или --full.
        export MAX_TTL="''${MAX_TTL:-0}"
        export MAX_AUTOTTL_DELTA="''${MAX_AUTOTTL_DELTA:-0}"
        export ENABLE_HTTP="''${ENABLE_HTTP:-0}"
        export ENABLE_HTTPS_TLS12="''${ENABLE_HTTPS_TLS12:-1}"
        export ENABLE_HTTPS_TLS13="''${ENABLE_HTTPS_TLS13:-0}"
        export ENABLE_HTTP3="''${ENABLE_HTTP3:-1}"
        echo "* быстрый скан: без развёртки по TTL, IPv4, TLS 1.2 + QUIC"
      fi

      exec blockcheck2
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

      interfaces = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        example = [ "eth0" ];
        description = ''
          Исходящие интерфейсы, трафик которых заворачивается в NFQUEUE.
          `null` — все, без разбора.

          ⚠️ Это стоит задать, если на машине есть VPN или Docker. Правило
          вешается на postrouting без привязки к интерфейсу, поэтому «все»
          означает буквально все:

          - **VPN.** Полный туннель (`tun0`, `wg0`, `amn0`…) забирает маршрут
            по умолчанию, и пакеты в туннель проходят postrouting раньше
            инкапсуляции. nfqws2 начинает десинхронизировать трафик ВНУТРИ
            туннеля: DPI провайдера его всё равно не видит, зато сервер на том
            конце получает подделанные пакеты и рвущиеся сессии. Заодно любая
            проверка «работает ли обход» становится ложной.
          - **Docker/LXC.** Трафик контейнеров на 443 идёт через бридж и тоже
            попадает в очередь — контейнеры получают чужую стратегию обхода.

          Апстримный zapret первой версии сужает свои правила до
          автоопределённых WAN-интерфейсов (`oifname @wanif`); здесь это
          решается явным списком, потому что декларативно он известен точно,
          а автоопределение молча ошибается при переключении сети.
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
      {
        # Имя идёт и в путь файла (/etc/zapret2/available/<имя>.conf), и в
        # значение `--comment=` внутри конфига. nfqws2 разбирает конфиг по
        # правилам шелла, поэтому кавычка или скобка в имени положат службу
        # целиком с невнятным «failed to split command line options».
        assertion = lib.all (p: builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" p.name != null) selected;
        message = ''
          services.zapret2: недопустимое имя пресета.
          Разрешены только [A-Za-z0-9._-], первый символ — буква или цифра.
          Проблемные: ${
            lib.concatStringsSep ", " (
              map (p: p.name) (
                lib.filter (p: builtins.match "[A-Za-z0-9][A-Za-z0-9._-]*" p.name == null) selected
              )
            )
          }
        '';
      }
    ];

    # Каталог доступных пресетов — декларативная часть SSOT.
    environment.etc = lib.mkMerge (
      map (p: {
        "zapret2/available/${p.name}.conf".source = confOf p;
      }) selected
      # Стратегии тех же пресетов в формате blockcheck2 — SSOT тот же, просто
      # другой вид. Поэтому «проверить свои стратегии» не требует ничего
      # переписывать руками и не может разойтись с тем, что реально работает.
      ++ map (kind: {
        "zapret2/blockcheck/${kind}.txt".source = candidateFile.${kind};
      }) candidateKinds
    );

    environment.systemPackages = [
      zapret2ctl
      zapret2-blockcheck
      cfg.package # сам blockcheck2 тоже под рукой — для ручного подбора
    ];

    systemd.services.zapret2 = {
      description = "DPI bypass (zapret2 / nfqws2)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      # Без этого правка стратегии НЕ ПРИМЕНЯЕТСЯ при пересборке, и это самый
      # неприятный из возможных багов: всё «прошло успешно», а nfqws2 остался
      # на прежней цепочке. ExecStart смотрит на /var/lib/zapret2/active.conf —
      # путь постоянный, юнит от правки пресета не меняется, systemd не видит
      # причины перезапускать. Хеш конфигов в триггере эту причину даёт.
      #
      # Триггерят ВСЕ доступные пресеты, а не только активный: какой активен —
      # состояние времени выполнения, на этапе сборки оно неизвестно.
      # Перезапуск лишний раз дешевле молчаливо старой стратегии.
      restartTriggers = map (p: confOf p) selected;

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
