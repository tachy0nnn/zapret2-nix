# ============================================================================
# Контракт пресета — единственный источник правды о том, что такое «пресет».
#
# Модуль зависит ОТ ЭТОГО ТИПА, а не от конкретных пресетов (DIP): любой
# пресет — хоть из нашей библиотеки, хоть присланный пользователем через
# `extraPresets` — проходит одну и ту же валидацию и взаимозаменяем (LSP).
#
# Терминология намеренно повторяет bol-van/zapret2 (profile, desync, payload,
# hostlist), чтобы апстримные доки и issue оставались применимы.
# ============================================================================
{ lib }:

let
  inherit (lib) types mkOption;

  # --------------------------------------------------------------------------
  # Профиль — одна «связка» фильтр → payload → цепочка воздействий.
  # В nfqws2 профили разделяются `--new`.
  # --------------------------------------------------------------------------
  profileType = types.submodule {
    options = {
      name = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "tls";
        description = ''
          Имя профиля (попадает в `--new=<name>`, видно в логах nfqws2).
          Первый профиль в пресете именовать нельзя — он идёт до первого `--new`.
        '';
      };

      filter = {
        tcp = mkOption {
          type = types.nullOr types.str;
          default = null;
          example = "443";
          description = ''
            TCP-порты (`--filter-tcp`). Допустимы диапазоны `80-443`,
            списки `80,443`, отрицание `~22`, `*` — все.
          '';
        };
        udp = mkOption {
          type = types.nullOr types.str;
          default = null;
          example = "443";
          description = "UDP-порты (`--filter-udp`), синтаксис как у tcp.";
        };
        l7 = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [ "tls" ];
          description = ''
            L7-протоколы (`--filter-l7`): http, tls, dtls, quic, wireguard,
            dht, discord, stun, xmpp, dns, mtproto, bt, utp_bt, known, unknown.
          '';
        };
        l3 = mkOption {
          type = types.nullOr (
            types.enum [
              "ipv4"
              "ipv6"
            ]
          );
          default = null;
          description = "L3-фильтр (`--filter-l3`). null — оба.";
        };
      };

      payload = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "tls_client_hello" ];
        description = ''
          Типы payload, которые обрабатывают Lua-функции (`--payload`).
          Полный список — в `nfqws2 --help`.
        '';
      };

      desync = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "fake:blob=fake_default_tls:tcp_md5"
          "multidisorder:pos=1,midsld"
        ];
        description = ''
          Цепочка воздействий на трафик — каждый элемент разворачивается в
          `--lua-desync=<элемент>`. Порядок сохраняется, это и есть стратегия.
        '';
      };

      hostlist = mkOption {
        type = types.nullOr (types.either types.bool (types.listOf types.str));
        default = null;
        example = false;
        description = ''
          Хостлист именно этого профиля:
          - `null` — наследовать `hostlist` пресета (обычный случай);
          - `false` — не применять хостлист вовсе (например для QUIC);
          - список доменов — свой хостлист вместо пресетного.
        '';
      };

      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "--dpi-desync-any-protocol" ];
        description = ''
          Аварийный люк: сырые аргументы nfqws2, которые не покрыты полями выше.
          Если чем-то пользуешься постоянно — заведи issue, добавим поле.
        '';
      };
    };
  };

  # --------------------------------------------------------------------------
  # Пресет — набор профилей + общий хостлист + метаданные о применимости.
  # Это ЧИСТЫЕ ДАННЫЕ: никакой логики, чтобы прислать пресет мог любой.
  # --------------------------------------------------------------------------
  presetType = types.submodule (
    { name, ... }:
    {
      options = {
        name = mkOption {
          type = types.str;
          default = name;
          description = "Идентификатор пресета (по умолчанию — ключ в наборе).";
        };

        description = mkOption {
          type = types.str;
          example = "YouTube + googlevideo: TLS ClientHello + QUIC";
          description = "Человекочитаемое описание: что именно чинит пресет.";
        };

        profiles = mkOption {
          type = types.listOf profileType;
          description = ''
            Профили nfqws2 по порядку. Минимум один — пресет без профилей
            не имеет смысла и отбрасывается проверкой.
          '';
        };

        hostlist = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [
            "youtube.com"
            "googlevideo.com"
          ];
          description = ''
            Домены, к которым применяется обход (поддомены подхватываются
            автоматически). Пустой список — применять ко всему трафику,
            попавшему под фильтры. Рекомендуется указывать: меньше риска
            задеть посторонние ресурсы.
          '';
        };

        hostlistExclude = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "Домены-исключения (`--hostlist-exclude`).";
        };

        meta = {
          testedOn = mkOption {
            type = types.listOf types.str;
            default = [ ];
            example = [ "Ростелеком" ];
            description = "Провайдеры/сети, где пресет подтверждённо работал.";
          };
          lastVerified = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "2026-07-27";
            description = ''
              Дата последней проверки (ГГГГ-ММ-ДД). Стратегии протухают —
              по этому полю видно, насколько пресету можно доверять.
            '';
          };
          reference = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Ссылка на источник стратегии (issue, обсуждение).";
          };
        };
      };
    }
  );
in
{
  inherit profileType presetType;
}
