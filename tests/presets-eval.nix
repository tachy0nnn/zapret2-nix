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

  confs = lib.mapAttrsToList (name: preset: {
    inherit name;
    file = zLib.mkPresetConf {
      inherit preset;
      qnum = 200;
    };
  }) evaluated;
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

      # Реальный разбор конфига движком. Ненулевой код возврата ожидаем
      # (в песочнице нет прав на setpcap/nfqueue) — важен ТОЛЬКО разбор опций.
      # ВАЖНО: переменную нельзя звать `out` — затрёт $out деривации.
      parsed="$(nfqws2 @${c.file} 2>&1 || true)"
      if echo "$parsed" | grep -qi 'unrecognized option\|invalid option\|bad argument'; then
        echo "   ОШИБКА: nfqws2 не принял опции:" >&2
        echo "$parsed" | grep -i 'unrecognized option\|invalid option\|bad argument' >&2
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
