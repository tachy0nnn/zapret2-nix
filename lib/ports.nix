# ============================================================================
# Извлечение портов из пресетов.
#
# Зачем: правила firewall должны заворачивать в NFQUEUE ровно те порты, по
# которым фильтруют профили. Держать их отдельной опцией — значит завести
# второй источник правды и однажды словить «пресет чинит 443, а в очередь
# отправляется 80». Поэтому порты ВЫВОДЯТСЯ из пресетов (SSOT).
#
# Не всякий фильтр сводится к списку портов: `*` (все) и `~22` (отрицание)
# принципиально неразрешимы в статический список. Тогда функция честно
# возвращает `undecidable`, а модуль требует явного указания портов.
# ============================================================================
{ lib }:

let
  inherit (lib)
    splitString
    unique
    flatten
    any
    hasPrefix
    ;

  # Один элемент фильтра: "443" | "80-443" | "~22" | "*"
  isUndecidable = item: item == "*" || hasPrefix "~" item;

  parseFilter =
    filterStr: if filterStr == null then [ ] else map lib.trim (splitString "," filterStr);
in
rec {
  inherit isUndecidable;

  # Все элементы фильтров заданного протокола по всем профилям всех пресетов.
  collect =
    proto: presets:
    flatten (map (preset: map (profile: parseFilter profile.filter.${proto}) preset.profiles) presets);

  # Есть ли среди них неразрешимые (`*` / `~`).
  hasUndecidable = proto: presets: any isUndecidable (collect proto presets);

  # Список портов для firewall. Диапазоны остаются как есть — форматирование
  # под конкретный бэкенд делает firewall-модуль.
  portsOf =
    proto: presets: unique (lib.filter (p: p != "" && !isUndecidable p) (collect proto presets));

  # nftables: `{ 80, 443, 1000-2000 }`
  toNft = ports: "{ ${lib.concatStringsSep ", " ports} }";

  # iptables multiport: диапазоны через двоеточие — `80,443,1000:2000`
  toIptables = ports: lib.concatStringsSep "," (map (p: lib.replaceStrings [ "-" ] [ ":" ] p) ports);
}
