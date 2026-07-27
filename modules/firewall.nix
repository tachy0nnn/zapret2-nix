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
              rule =
                proto: portList:
                lib.optionalString (
                  portList != [ ]
                ) "${proto} dport ${ports.toNft portList} ${limit}queue flags bypass to ${qnum}";
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

          rule =
            op: proto: portList:
            lib.optionalString (portList != [ ]) ''
              ip46tables -t mangle ${op} POSTROUTING -p ${proto} -m multiport --dports ${ports.toIptables portList} ${limit}-m mark ! --mark ${mark}/${mark} -j NFQUEUE --queue-num ${qnum} --queue-bypass
            '';
        in
        {
          networking.firewall.extraCommands = ''
            ${rule "-I" "tcp" tcpPorts}
            ${rule "-I" "udp" udpPorts}
          '';
          networking.firewall.extraStopCommands = ''
            ${rule "-D" "tcp" tcpPorts}
            ${rule "-D" "udp" udpPorts}
          '';
        }
      ))
    ]
  );
}
