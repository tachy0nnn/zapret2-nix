# ============================================================================
# Рендер пресета в conf-файл для `nfqws2 @<file>`.
#
# Чистая функция: пресет (данные) → текст конфига. Ничего не знает ни про
# systemd, ни про firewall (ISP) — поэтому тестируется в отрыве от системы.
#
# Формат проверен на nfqws2 v1.0.x:
#   • `@file` должен быть ЕДИНСТВЕННЫМ аргументом (остальные игнорируются),
#     поэтому глобальные опции вроде --qnum кладём внутрь файла;
#   • поддерживаются комментарии `#` и пустые строки;
#   • профили разделяются `--new`, аргументы можно переносить по строкам.
# ============================================================================
{ lib, pkgs }:

let
  inherit (lib)
    concatStringsSep
    optional
    imap0
    ;

  # Хостлист — отдельный файл в store (nfqws2 читает его сам, gzip не нужен).
  mkHostlistFile =
    name: domains: pkgs.writeText "zapret2-hostlist-${name}" (concatStringsSep "\n" domains + "\n");

  # --------------------------------------------------------------------------
  # Текст, пригодный для строки-комментария conf-файла.
  #
  # nfqws2 разбивает файл на токены ПО ПРАВИЛАМ ШЕЛЛА и только потом отбрасывает
  # то, что начинается с `#`. Поэтому спецсимвол внутри комментария ломает не
  # комментарий, а ВЕСЬ файл: nfqws2 отвечает «failed to split command line
  # options from file» и не запускается вовсе.
  #
  # Ломающий набор снят с nfqws2 v1.0.3 перебором: ( ) { } ' " ` & | ; < > \
  # Безопасны, в частности: $ * ? [ ] ! ~ = : , + - / % @ ^ и любая кириллица.
  #
  # Актуально это не для наших пресетов, а для чужих: `description` — свободный
  # текст, и «Discord (голос)» в extraPresets положил бы службу целиком, причём
  # с сообщением, по которому причину не угадать.
  safeComment =
    lib.replaceStrings
      [
        "("
        ")"
        "{"
        "}"
        "'"
        "\""
        "`"
        "&"
        "|"
        ";"
        "<"
        ">"
        "\\"
      ]
      [
        "["
        "]"
        "["
        "]"
        ""
        ""
        ""
        "+"
        "/"
        ","
        ""
        ""
        "/"
      ];
in
rec {
  inherit mkHostlistFile safeComment;

  # --------------------------------------------------------------------------
  # Аргументы одного профиля (без ведущего --new — его добавляет renderProfiles).
  #
  # Порядок аргументов повторяет апстримный config.default: фильтры → хостлист
  # → payload → воздействия. Так сгенерированный конфиг легко сверять с
  # примерами из документации zapret2.
  # --------------------------------------------------------------------------
  renderProfile =
    {
      presetName,
      presetHostlist,
      presetExclude,
    }:
    profile:
    let
      f = profile.filter;

      # Какой хостлист у профиля: свой / унаследованный / отключён.
      effectiveHostlist =
        if profile.hostlist == null then
          presetHostlist
        else if profile.hostlist == false then
          [ ]
        else if profile.hostlist == true then
          presetHostlist
        else
          profile.hostlist;

      hostlistArgs =
        optional (
          effectiveHostlist != [ ]
        ) "--hostlist=${mkHostlistFile "${presetName}-in" effectiveHostlist}"
        ++ optional (
          presetExclude != [ ]
        ) "--hostlist-exclude=${mkHostlistFile "${presetName}-ex" presetExclude}";
    in
    concatStringsSep " " (
      optional (f.l3 != null) "--filter-l3=${f.l3}"
      ++ optional (f.tcp != null) "--filter-tcp=${f.tcp}"
      ++ optional (f.udp != null) "--filter-udp=${f.udp}"
      ++ optional (f.l7 != [ ]) "--filter-l7=${concatStringsSep "," f.l7}"
      ++ hostlistArgs
      ++ optional (profile.payload != [ ]) "--payload=${concatStringsSep "," profile.payload}"
      ++ map (d: "--lua-desync=${d}") profile.desync
      ++ profile.extraArgs
    );

  # --------------------------------------------------------------------------
  # Профили целиком. Первый идёт без `--new` (он и есть первый профиль),
  # каждый следующий начинается с `--new` либо `--new=<имя>`.
  # --------------------------------------------------------------------------
  renderProfiles =
    ctx: profiles:
    concatStringsSep "\n" (
      imap0 (
        i: p:
        let
          body = renderProfile ctx p;
        in
        if i == 0 then body else "${if p.name != null then "--new=${p.name}" else "--new"} ${body}"
      ) profiles
    );

  # --------------------------------------------------------------------------
  # Полный conf-файл пресета.
  #
  # `luaInit` и `fwmark` приходят снаружи, а не зашиты здесь: пути к Lua-файлам
  # принадлежат пакету, а рендер про пакет знать не должен (DIP). Модуль их и
  # подставляет.
  #
  # ⚠️ Без --lua-init nfqws2 стартует, разбирает опции, а потом падает с
  # «desync function 'fake' does not exist»: функции воздействий (fake,
  # multisplit, multidisorder…) определены именно в этих Lua-файлах, в самом
  # бинаре их нет. Поймано VM-тестом.
  # --------------------------------------------------------------------------
  renderPreset =
    {
      preset,
      qnum,
      fwmark,
      luaInit,
    }:
    let
      ctx = {
        presetName = preset.name;
        presetHostlist = preset.hostlist;
        presetExclude = preset.hostlistExclude;
      };
    in
    ''
      # Сгенерировано zapret2-nix. Правки будут потеряны при пересборке.
      # Пресет: ${safeComment preset.name} — ${safeComment preset.description}
      ${lib.optionalString (
        preset.meta.lastVerified != null
      ) "# Последняя проверка: ${safeComment preset.meta.lastVerified}"}
      --qnum=${toString qnum}
      --comment=zapret2-nix:${preset.name}

      # Метка на пакетах, которые порождает сам nfqws2 — по ней правило
      # firewall отсеивает их и не отправляет в очередь повторно.
      --fwmark=${fwmark}

      # Библиотека стратегий. Порядок важен: zapret-lib определяет базу,
      # остальные — функции воздействий поверх неё.
      ${concatStringsSep "\n" (map (f: "--lua-init=@${f}") luaInit)}

      ${renderProfiles ctx preset.profiles}
    '';

  # Готовый файл в store.
  mkPresetConf = args: pkgs.writeText "zapret2-${args.preset.name}.conf" (renderPreset args);

  # --------------------------------------------------------------------------
  # Стратегия профиля в формате списка blockcheck2 (blockcheck2.d/custom).
  #
  # Переносятся ТОЛЬКО payload и цепочка воздействий. Фильтры и хостлист
  # намеренно отбрасываются: blockcheck2 сам сужает тест до IP проверяемого
  # домена своими правилами, а наш `--filter-tcp`/`--hostlist` там либо
  # избыточен, либо (хостлист с чужим доменом) отменил бы воздействие целиком
  # и дал бы ложное «стратегия не работает».
  # --------------------------------------------------------------------------
  renderCandidate =
    profile:
    concatStringsSep " " (
      optional (profile.payload != [ ]) "--payload=${concatStringsSep "," profile.payload}"
      ++ map (d: "--lua-desync=${d}") profile.desync
      ++ profile.extraArgs
    );

  # К какому тесту blockcheck2 относится профиль. blockcheck2 держит отдельные
  # списки стратегий на http / tls / quic, потому что проверяет их разными
  # запросами curl. Определяем по payload, а если он не задан — по L7-фильтру.
  #
  # `null` — профиль не отображается ни на один тест blockcheck2 (например
  # голос Discord: STUN не проверить обычным curl).
  candidateKind =
    profile:
    let
      has = x: lib.elem x profile.payload || lib.elem x profile.filter.l7;
    in
    if has "quic_initial" || has "quic" then
      "quic"
    else if has "tls_client_hello" || has "tls" then
      "tls"
    else if has "http_req" || has "http" then
      "http"
    else
      null;

  # --------------------------------------------------------------------------
  # Список стратегий одного вида по набору пресетов — файл для blockcheck2.
  #
  # Одинаковые цепочки объединяются: youtube и general делят одну TLS-стратегию,
  # и гонять её дважды — только время. В комментарии перед строкой видно, из
  # каких пресетов она пришла, поэтому по выводу blockcheck2 понятно, какой
  # именно пресет сработал.
  # --------------------------------------------------------------------------
  candidateLines =
    kind: presets:
    let
      pairs = lib.concatMap (
        preset:
        map (profile: {
          line = renderCandidate profile;
          inherit (preset) name;
        }) (lib.filter (profile: candidateKind profile == kind) preset.profiles)
      ) presets;
    in
    lib.mapAttrsToList (line: xs: {
      inherit line;
      presets = lib.unique (map (x: x.name) xs);
    }) (lib.groupBy (x: x.line) pairs);

  mkCandidateFile =
    kind: presets:
    let
      entries = candidateLines kind presets;
    in
    pkgs.writeText "zapret2-blockcheck-${kind}.txt" (
      concatStringsSep "\n" (
        [
          "# Сгенерировано zapret2-nix: стратегии вида ${kind} из объявленных пресетов."
          "# Проверяются командой: zapret2-blockcheck --presets"
        ]
        ++ lib.concatMap (e: [
          "# пресет(ы): ${concatStringsSep ", " e.presets}"
          e.line
        ]) entries
      )
      + "\n"
    );
}
