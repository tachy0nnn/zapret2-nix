# ============================================================================
# Общий сценарий виртуалочного теста, параметризованный бэкендом firewall.
#
# Один сценарий на оба бэкенда — это и есть проверка LSP: nftables и iptables
# должны быть взаимозаменяемы с точки зрения наблюдаемого поведения.
# ============================================================================
{
  pkgs,
  self,
  backend,
}:

pkgs.testers.runNixOSTest {
  name = "zapret2-${backend}";

  nodes.machine =
    { ... }:
    {
      imports = [ self.nixosModules.default ];

      networking.nftables.enable = backend == "nftables";
      networking.firewall.enable = true;

      services.zapret2 = {
        enable = true;
        presets = [
          "general"
          "youtube"
        ];
        defaultPreset = "general";
        firewall.backend = backend;
      };
    };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    with subtest("служба поднимается"):
        machine.wait_for_unit("zapret2.service")
        machine.succeed("systemctl is-active zapret2.service")

    with subtest("каталог доступных пресетов декларативен"):
        machine.succeed("test -f /etc/zapret2/available/general.conf")
        machine.succeed("test -f /etc/zapret2/available/youtube.conf")
        # конфиг сгенерирован осмысленно, а не пустой
        machine.succeed("grep -q -- '--qnum=200' /etc/zapret2/available/general.conf")
        machine.succeed("grep -q -- '--lua-desync=' /etc/zapret2/available/general.conf")

    with subtest("активный пресет — симлинк на дефолтный"):
        machine.succeed("test -L /var/lib/zapret2/active.conf")
        active = machine.succeed("readlink -f /var/lib/zapret2/active.conf")
        assert "general" in active, f"ожидался general, получено: {active}"

    with subtest("трафик заворачивается в NFQUEUE"):
        ${
          if backend == "nftables" then
            ''
              rules = machine.succeed("nft list table inet zapret2")
              assert "queue" in rules, f"нет queue-правила:\n{rules}"
              assert "200" in rules, f"не тот номер очереди:\n{rules}"
              # собственные пакеты nfqws2 не должны попадать в очередь повторно
              assert "0x40000000" in rules, f"нет защиты от петли по метке:\n{rules}"
            ''
          else
            ''
              rules = machine.succeed("iptables -t mangle -S POSTROUTING")
              assert "NFQUEUE" in rules, f"нет NFQUEUE-правила:\n{rules}"
              assert "--queue-num 200" in rules, f"не тот номер очереди:\n{rules}"
              assert "0x40000000" in rules, f"нет защиты от петли по метке:\n{rules}"
            ''
        }

    with subtest("zapret2ctl показывает состояние"):
        out = machine.succeed("zapret2ctl status")
        assert "general" in out, f"status не показывает активный пресет:\n{out}"
        listed = machine.succeed("zapret2ctl list")
        assert "youtube" in listed and "general" in listed, f"list неполон:\n{listed}"

    with subtest("переключение пресета БЕЗ пересборки системы"):
        machine.succeed("zapret2ctl switch youtube")
        machine.wait_for_unit("zapret2.service")
        active = machine.succeed("readlink -f /var/lib/zapret2/active.conf")
        assert "youtube" in active, f"пресет не переключился: {active}"
        out = machine.succeed("zapret2ctl status")
        assert "youtube" in out, f"status не отражает переключение:\n{out}"

    with subtest("несуществующий пресет отвергается"):
        machine.fail("zapret2ctl switch nonexistent-preset")
        # активный не должен пострадать от неудачной попытки
        active = machine.succeed("readlink -f /var/lib/zapret2/active.conf")
        assert "youtube" in active, f"неудачное переключение сломало активный пресет: {active}"

    with subtest("восстановление после исчезновения активного пресета"):
        machine.succeed("systemctl stop zapret2.service")
        machine.succeed("rm -f /var/lib/zapret2/active.conf")
        machine.succeed("systemctl start zapret2.service")
        machine.wait_for_unit("zapret2.service")
        active = machine.succeed("readlink -f /var/lib/zapret2/active.conf")
        assert "general" in active, f"не откатились на defaultPreset: {active}"

    with subtest("reload firewall переживает ОТСУТСТВИЕ наших правил"):
        # Регрессия 2026-07-31. Раньше проверялся только путь stop → start, где
        # правила на момент удаления ЕСТЬ. А в жизни самый частый путь другой:
        # модуль включают на работающей системе, nixos-rebuild перезагружает
        # firewall, extraStopCommands пытается снять правила, которых ещё нет,
        # iptables возвращает 1 — и активация ВСЕЙ конфигурации падает с
        # «Failed to reload firewall.service».
        # Здесь это состояние воспроизводится явно: убираем правила и грузим
        # конфиг заново. Reload обязан пройти, а правила — вернуться.
        ${
          if backend == "nftables" then
            ''
              machine.succeed("nft delete table inet zapret2")
              machine.succeed("systemctl reload-or-restart nftables.service")
              machine.succeed("nft list table inet zapret2")
            ''
          else
            ''
              def nfqueue_rules():
                  return machine.succeed("iptables -t mangle -S POSTROUTING").count("NFQUEUE")

              expected = nfqueue_rules()
              assert expected > 0, "правил NFQUEUE нет ещё до начала проверки"

              # 1. Правил нет — reload обязан пройти и восстановить их.
              machine.succeed("iptables -t mangle -F POSTROUTING")
              machine.succeed("systemctl reload firewall.service")
              assert nfqueue_rules() == expected, (
                  f"после reload без правил их {nfqueue_rules()}, ожидалось {expected}"
              )

              # 2. Правила есть — удаление реальное, задвоения быть не должно.
              machine.succeed("systemctl reload firewall.service")
              assert nfqueue_rules() == expected, (
                  f"повторный reload задвоил или потерял правила: "
                  f"{nfqueue_rules()} вместо {expected}"
              )
            ''
        }

    with subtest("правила снимаются вместе с firewall — сеть не остаётся дырявой"):
        ${
          if backend == "nftables" then
            ''
              machine.succeed("systemctl stop nftables.service")
              machine.fail("nft list table inet zapret2")
              machine.succeed("systemctl start nftables.service")
              machine.succeed("nft list table inet zapret2")
            ''
          else
            ''
              machine.succeed("systemctl stop firewall.service")
              rules = machine.succeed("iptables -t mangle -S POSTROUTING")
              assert "NFQUEUE" not in rules, (
                  f"правила пережили остановку firewall — трафик пойдёт в мёртвую очередь:\n{rules}"
              )
              machine.succeed("systemctl start firewall.service")
              rules = machine.succeed("iptables -t mangle -S POSTROUTING")
              assert "NFQUEUE" in rules, f"правила не вернулись после старта firewall:\n{rules}"
            ''
        }
  '';
}
