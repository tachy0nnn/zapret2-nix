# ============================================================================
# Проверка контракта пресетов — без виртуалки, быстро.
#
# 1. Каждый библиотечный пресет проходит валидацию типом presetType.
# 2. Рендерится в непустой конфиг.
# 3. НАСТОЯЩИЙ nfqws2 разбирает этот конфиг без «unrecognized option».
#
# Пункт 3 — самый ценный: опечатка в имени опции («--lua-desyn=») иначе
# всплыла бы только у пользователя, и выглядела бы как «обход не работает».
# ============================================================================
{ pkgs }:

let
  inherit (pkgs) lib;
  zLib = import ../lib { inherit lib pkgs; };

  raw = zLib.loadPresets ../presets;

  # Прогон через тип: недостающие поля, опечатки в ключах и неверные типы
  # упадут прямо здесь, с внятным сообщением от модульной системы.
  evaluated =
    (lib.evalModules {
      modules = [
        {
          options.presets = lib.mkOption { type = lib.types.attrsOf zLib.presetType; };
        }
        { presets = raw; }
      ];
    }).config.presets;

  # Те же параметры, что подставляет модуль в реальной системе — иначе тест
  # проверял бы не то, что запускается.
  luaInit = map (f: "${pkgs.zapret2}/share/zapret2/lua/${f}") [
    "zapret-lib.lua"
    "zapret-antidpi.lua"
    "zapret-auto.lua"
  ];

  mkConf =
    preset:
    zLib.mkPresetConf {
      inherit preset luaInit;
      qnum = 200;
      fwmark = "0x40000000";
    };

  # ---------------------------------------------------------------------------
  # Пресет с враждебным описанием. Регрессия, найденная 2026-08-05.
  #
  # nfqws2 токенизирует conf-файл по правилам шелла ДО того, как отбросит
  # строки-комментарии. Из-за этого скобка или кавычка в `description` ломала не
  # комментарий, а весь файл: «failed to split command line options from file»,
  # служба не поднималась вообще. Проявлялось только у чужих пресетов —
  # `description` там свободный текст, и «Discord (голос)» уже достаточно.
  #
  # Набор символов ниже — ровно тот, что валит парсер. Тест обязан проходить:
  # рендер их обезвреживает.
  hostile = {
    name = "hostile-description";
    description = "скобки [нет: (вот)] кавычки ' и \" бэктик ` амперсанд & труба | точка с запятой ; угол < > фигурные { } слеш \\";
    hostlist = [ ];
    hostlistExclude = [ ];
    meta = {
      testedOn = [ ];
      lastVerified = null;
      reference = null;
    };
    profiles = [
      {
        name = null;
        filter = {
          tcp = "443";
          udp = null;
          l7 = [ "tls" ];
          l3 = null;
        };
        payload = [ "tls_client_hello" ];
        desync = [ "fake:blob=fake_default_tls:tcp_ts=-1000" ];
        hostlist = null;
        extraArgs = [ ];
      }
    ];
  };

  confs =
    lib.mapAttrsToList (name: preset: {
      inherit name;
      file = mkConf preset;
    }) evaluated
    ++ [
      {
        name = hostile.name;
        file = mkConf hostile;
      }
    ];
in
pkgs.runCommand "zapret2-presets-eval"
  {
    nativeBuildInputs = [ pkgs.zapret2 ];
    passthru.presetNames = lib.attrNames evaluated;
  }
  ''
    fail=0

    ${lib.concatMapStringsSep "\n" (c: ''
      echo "==> пресет: ${c.name}"

      if ! grep -q -- '--qnum=' ${c.file}; then
        echo "   ОШИБКА: в конфиге нет --qnum" >&2; fail=1
      fi
      if ! grep -q -- '--lua-desync=' ${c.file}; then
        echo "   ОШИБКА: в конфиге нет ни одного --lua-desync (пресет ничего не делает)" >&2; fail=1
      fi

      # Регрессия, уже случившаяся однажды: без --lua-init функции воздействий
      # (fake, multisplit, …) не определены, и служба падает на старте с
      # «desync function ... does not exist». Разбор опций при этом проходит,
      # и локально nfqws2 молчит — поймать можно только структурно.
      if ! grep -q -- '--lua-init=@' ${c.file}; then
        echo "   ОШИБКА: в конфиге нет --lua-init — стратегии не будут определены" >&2; fail=1
      fi
      # Без --fwmark nfqws2 не пометит свои пакеты, и правило firewall,
      # отсеивающее их по метке, пропустит трафик по кругу.
      if ! grep -q -- '--fwmark=' ${c.file}; then
        echo "   ОШИБКА: в конфиге нет --fwmark — возможна петля в NFQUEUE" >&2; fail=1
      fi

      # Реальный разбор конфига движком. Ненулевой код возврата ожидаем
      # (в песочнице нет прав на setpcap/nfqueue) — важен ТОЛЬКО разбор опций.
      # ВАЖНО: переменную нельзя звать `out` — затрёт $out деривации.
      parsed="$(nfqws2 @${c.file} 2>&1 || true)"
      # Спецсимвол в комментарии валит разбор файла ЦЕЛИКОМ, ещё до опций.
      # Отдельная проверка, потому что иначе видно лишь «профилей не найдено»,
      # и причина не угадывается.
      if echo "$parsed" | grep -qi 'failed to split'; then
        echo "   ОШИБКА: nfqws2 не смог разобрать файл — спецсимвол в комментарии?" >&2
        echo "$parsed" | grep -i 'failed to split' >&2
        fail=1
      fi
      if echo "$parsed" | grep -qi 'unrecognized option\|invalid option\|bad argument'; then
        echo "   ОШИБКА: nfqws2 не принял опции:" >&2
        echo "$parsed" | grep -i 'unrecognized option\|invalid option\|bad argument' >&2
        fail=1
      fi
      # Функции воздействий определены в Lua-модулях. Если забыть --lua-init,
      # опции разберутся, но на старте будет «desync function ... does not
      # exist» — этот баг однажды уже проехал сюда и всплыл только в VM.
      if echo "$parsed" | grep -qi 'does not exist\|lua error\|cannot open'; then
        echo "   ОШИБКА: стратегия не разрешилась (проверь --lua-init):" >&2
        echo "$parsed" | grep -i 'does not exist\|lua error\|cannot open' >&2
        fail=1
      fi
      if ! echo "$parsed" | grep -q 'desync profile'; then
        echo "   ОШИБКА: nfqws2 не увидел ни одного профиля" >&2
        echo "$parsed" >&2
        fail=1
      fi
    '') confs}

    if [ "$fail" -ne 0 ]; then
      echo "" >&2
      echo "Проверка пресетов провалена." >&2
      exit 1
    fi

    echo "Все пресеты валидны: ${lib.concatStringsSep ", " (lib.attrNames evaluated)}"
    touch $out
  ''
