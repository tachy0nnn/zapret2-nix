# ============================================================================
# Заворачивание трафика в NFQUEUE — единственное место в проекте, которое
# знает про firewall (SRP). Меняется только когда меняется firewall-стек,
# а не когда протухла очередная стратегия.
#
# Два бэкенда за одним поведением (LSP): nftables и iptables. Выбор по
# умолчанию автоматический — по тому, что включено в системе.
#
# Отдельно от zapret2.nix, потому что это другая причина для изменений и
# другая предметная область: пресеты про «как дурить DPI», это — про
# «как доставить пакеты до nfqws2».
# ============================================================================
{ config, lib, ... }:

let
  cfg = config.services.zapret2;
  fw = cfg.firewall;

  ports = import ../lib/ports.nix { inherit lib; };

  presets = cfg._resolvedPresets;

  # Порты: либо явно заданы пользователем, либо выведены из пресетов (SSOT).
  tcpPorts = if fw.ports.tcp != null then fw.ports.tcp else ports.portsOf "tcp" presets;
  udpPorts = if fw.ports.udp != null then fw.ports.udp else ports.portsOf "udp" presets;

  qnum = toString cfg.qnum;
  mark = fw.desyncMark;

  # В режиме "first" обрабатываем только начало соединения — этого хватает
  # большинству DPI и заметно дешевле по CPU. "full" гоняет через nfqws2 все
  # пакеты: нужно там, где DPI смотрит сессию целиком.
  connLimit = fw.connbytesLimit;

  useNft =
    if fw.backend == "auto" then config.networking.nftables.enable else fw.backend == "nftables";

  # Сужение до исходящих интерфейсов. Пустой список трактуем как «все» —
  # иначе получилось бы правило, не подходящее ни к одному пакету, то есть
  # молча выключенный обход.
  ifaces = if fw.interfaces == null || fw.interfaces == [ ] then null else fw.interfaces;
in
{
  config = lib.mkIf (cfg.enable && fw.enable) (
    lib.mkMerge [
      {
        assertions = [
          {
            assertion = fw.ports.tcp != null || !(ports.hasUndecidable "tcp" presets);
            message = ''
              services.zapret2: один из пресетов использует TCP-фильтр `*` или `~`,
              из которого нельзя вывести список портов для firewall.
              Укажи порты явно: services.zapret2.firewall.ports.tcp = [ "80" "443" ];
            '';
          }
          {
            assertion = fw.ports.udp != null || !(ports.hasUndecidable "udp" presets);
            message = ''
              services.zapret2: один из пресетов использует UDP-фильтр `*` или `~`
              (например пресет discord — голос ходит по произвольным портам).
              Укажи порты явно: services.zapret2.firewall.ports.udp = [ "443" "50000-65535" ];
            '';
          }
          {
            assertion = tcpPorts != [ ] || udpPorts != [ ];
            message = ''
              services.zapret2: не удалось определить ни одного порта для перехвата.
              Проверь, что выбранные пресеты задают filter.tcp / filter.udp,
              либо укажи services.zapret2.firewall.ports.* вручную.
            '';
          }
        ];
      }

      # ---------------------------------------------------------------------
      # nftables — то, чего не умеет модуль services.zapret для первой версии
      # (там прямая заглушка «настраивай firewall руками»).
      # ---------------------------------------------------------------------
      (lib.mkIf useNft {
        networking.nftables.tables.zapret2 = {
          family = "inet";
          content =
            let
              # Пакеты, которые nfqws2 сам отправил, помечены DESYNC_MARK —
              # их нельзя возвращать в очередь, иначе получим петлю.
              skipOwn = "meta mark and ${mark} == ${mark} return";
              limit = lib.optionalString (connLimit > 0) "ct original packets 1-${toString connLimit} ";
              oif =
                lib.optionalString (ifaces != null)
                  "oifname { ${lib.concatMapStringsSep ", " (i: ''"${i}"'') ifaces} } ";
              rule =
                proto: portList:
                lib.optionalString (
                  portList != [ ]
                ) "${oif}${proto} dport ${ports.toNft portList} ${limit}queue flags bypass to ${qnum}";
            in
            ''
              chain zapret2_postrouting {
                type filter hook postrouting priority mangle; policy accept;
                ${skipOwn}
                ${rule "tcp" tcpPorts}
                ${rule "udp" udpPorts}
              }
            '';
        };
      })

      # ---------------------------------------------------------------------
      # iptables — extraStopCommands обязателен: без него правила переживают
      # остановку сервиса и трафик уходит в несуществующую очередь.
      # ---------------------------------------------------------------------
      (lib.mkIf (!useNft) (
        let
          limit =
            lib.optionalString (connLimit > 0)
              "-m connbytes --connbytes-dir=original --connbytes-mode=packets --connbytes 1:${toString connLimit} ";

          # iptables принимает `-o` только по одному интерфейсу на правило,
          # поэтому здесь список разворачивается в несколько правил. Пустая
          # строка — «без привязки к интерфейсу», ровно одно правило.
          oifs = if ifaces == null then [ "" ] else map (i: "-o ${i} ") ifaces;

          # Тело правила одно на добавление и удаление — иначе рассинхрон:
          # `-D` удаляет правило только при ПОБУКВЕННОМ совпадении с `-I`.
          body =
            proto: portList: oif:
            "POSTROUTING ${oif}-p ${proto} -m multiport --dports ${ports.toIptables portList} ${limit}-m mark ! --mark ${mark}/${mark} -j NFQUEUE --queue-num ${qnum} --queue-bypass";

          add =
            proto: portList:
            lib.optionalString (portList != [ ]) (
              lib.concatMapStrings (oif: ''
                ip46tables -t mangle -I ${body proto portList oif}
              '') oifs
            );

          # `|| true` тут ОБЯЗАТЕЛЕН, и это не небрежность.
          # extraStopCommands выполняется не только при остановке, но и при
          # КАЖДОЙ перезагрузке firewall — в том числе самой первой, на системе,
          # где наших правил ещё нет. iptables на `-D` несуществующего правила
          # отвечает «Bad rule (does a matching rule exist in that chain?)» и
          # возвращает 1, а скрипт firewall работает под `set -e`. Без `|| true`
          # падает весь reload, а вместе с ним и активация всей конфигурации:
          # nixos-rebuild выходит с «Failed to reload firewall.service».
          # Ровно это и случилось при первом включении модуля 2026-07-31.
          del =
            proto: portList:
            lib.optionalString (portList != [ ]) (
              lib.concatMapStrings (oif: ''
                ip46tables -t mangle -D ${body proto portList oif} || true
              '') oifs
            );
        in
        {
          networking.firewall.extraCommands = ''
            ${add "tcp" tcpPorts}
            ${add "udp" udpPorts}
          '';
          networking.firewall.extraStopCommands = ''
            ${del "tcp" tcpPorts}
            ${del "udp" udpPorts}
          '';
        }
      ))
    ]
  );
}
