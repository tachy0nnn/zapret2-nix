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

let
  useNft = backend == "nftables";

  # Различия бэкендов — ОДНОСТРОЧНЫМИ значениями, а не блоками кода.
  # Многострочная интерполяция внутри testScript ломает отступы Python:
  # Nix вставляет содержимое как есть, и вложенный блок оказывается на нулевой
  # колонке («Expected an indented block after `with` statement»).
  fw = {
    unit = if useNft then "nftables.service" else "firewall.service";
    # команда, убирающая наши правила
    drop = if useNft then "nft delete table inet zapret2" else "iptables -t mangle -F POSTROUTING";
    # команда, выводящая текущие правила
    list = if useNft then "nft list table inet zapret2" else "iptables -t mangle -S POSTROUTING";
    # подстрока, по числу которой считаем правила. Для nft это ровно тот текст,
    # который печатает `nft list` для нашего правила — «queue flags bypass to N»,
    # а не «queue num N»: последнее относится к другому синтаксису и не совпадёт.
    marker = if useNft then "queue flags bypass to" else "NFQUEUE";
  };
in

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
        # Сужение до одного интерфейса проверяется вместе с остальным: без него
        # правило ловит и трафик в VPN-туннель, и трафик контейнеров.
        firewall.interfaces = [ "eth1" ];
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

    with subtest("правило сужено до заданного интерфейса"):
        # Иначе NFQUEUE ловит ВСЁ, включая пакеты в VPN-туннель (там обход
        # бесполезен, а сессии рвутся) и трафик docker-бриджей.
        rules = machine.succeed("${fw.list}")
        assert "eth1" in rules, f"правило не привязано к интерфейсу:\n{rules}"

    with subtest("стратегии выгружены в формате blockcheck2"):
        machine.succeed("test -s /etc/zapret2/blockcheck/tls.txt")
        tls = machine.succeed("cat /etc/zapret2/blockcheck/tls.txt")
        assert "--lua-desync=" in tls, f"в списке нет ни одной стратегии:\n{tls}"
        assert "--payload=tls_client_hello" in tls, f"в списке нет payload:\n{tls}"
        # Фильтры и хостлист в список попадать не должны: blockcheck2 сужает
        # тест сам, а чужой хостлист отменил бы воздействие и дал бы ложное
        # «стратегия не работает».
        assert "--filter-" not in tls, f"в список утёк фильтр:\n{tls}"
        assert "--hostlist" not in tls, f"в список утёк хостлист:\n{tls}"

    with subtest("blockcheck отказывается работать через туннель"):
        # Самая дорогая из возможных ошибок подбора: через VPN заблокированное
        # открывается само, и blockcheck2 объявляет рабочей любую стратегию.
        machine.succeed("ip link add wg-test type dummy")
        machine.succeed("ip link set wg-test up")
        machine.succeed("ip addr add 10.77.0.1/24 dev wg-test")
        machine.succeed("ip route add 0.0.0.0/1 dev wg-test")
        out = machine.fail("zapret2-blockcheck --presets example.com 2>&1")
        assert "wg-test" in out, f"туннель не назван в отказе:\n{out}"
        # Служба не должна пострадать от отвергнутого запуска.
        machine.succeed("systemctl is-active zapret2.service")
        machine.succeed("ip route del 0.0.0.0/1 dev wg-test")
        machine.succeed("ip link del wg-test")

    with subtest("zapret2ctl показывает состояние"):
        out = machine.succeed("zapret2ctl status")
        assert "general" in out, f"status не показывает активный пресет:\n{out}"
        # Регрессия: current() использовал `readlink -f` и разрешал ссылку до
        # конца, показывая /nix/store/<хеш>-zapret2-general вместо «general».
        assert "/nix/store" not in out and "-zapret2-" not in out, (
            f"status показывает путь в store вместо имени пресета:\n{out}"
        )
        listed = machine.succeed("zapret2ctl list")
        assert "youtube" in listed and "general" in listed, f"list неполон:\n{listed}"
        # По той же причине активный пресет не помечался звёздочкой.
        assert "* general" in listed, f"активный пресет не отмечен в list:\n{listed}"

    with subtest("status читается БЕЗ root"):
        # Регрессия: StateDirectoryMode=0700 не давал обычному пользователю
        # войти в /var/lib/zapret2, проверка `[ -L ]` падала, и status врал
        # «(не задан)», хотя пресет выставлен.
        out = machine.succeed("runuser -u nobody -- zapret2ctl status")
        assert "general" in out, f"без root status не видит активный пресет:\n{out}"
        assert "не задан" not in out, f"без root status врёт «(не задан)»:\n{out}"

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
        expected = machine.succeed("${fw.list}").count("${fw.marker}")
        assert expected > 0, "правил нет ещё до начала проверки — тест бессмыслен"

        # 1. Правил нет — reload обязан пройти и восстановить их.
        machine.succeed("${fw.drop}")
        machine.succeed("systemctl reload-or-restart ${fw.unit}")
        after = machine.succeed("${fw.list}").count("${fw.marker}")
        assert after == expected, f"после reload без правил их {after}, ожидалось {expected}"

        # 2. Правила есть — удаление реальное, задвоения быть не должно.
        machine.succeed("systemctl reload-or-restart ${fw.unit}")
        again = machine.succeed("${fw.list}").count("${fw.marker}")
        assert again == expected, f"повторный reload дал {again} правил вместо {expected}"

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
