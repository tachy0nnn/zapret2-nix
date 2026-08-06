# ============================================================================
# Публичная библиотека zapret2-nix.
#
# Доступна как `zapret2-nix.lib.${system}` — чтобы пресеты и рендер можно было
# переиспользовать вне нашего модуля (например, в своём модуле или в тестах).
# ============================================================================
{ lib, pkgs }:

let
  types' = import ./types.nix { inherit lib; };
  render = import ./render.nix { inherit lib pkgs; };
in
{
  inherit (types') profileType presetType;
  inherit (render)
    renderPreset
    renderProfile
    renderProfiles
    mkPresetConf
    mkHostlistFile
    safeComment
    renderCandidate
    candidateKind
    candidateLines
    mkCandidateFile
    ;

  # --------------------------------------------------------------------------
  # Загрузка каталога с пресетами: `<dir>/<name>.nix` → { <name> = {...}; }.
  # Пропускаются служебные файлы: начинающиеся с `_` и `default.nix`
  # (последний — точка входа самого каталога, иначе получим рекурсию).
  #
  # Каждый файл — чистый атрибутсет по контракту presetType. Валидация
  # происходит там, где пресет попадает в опцию модуля (тип сделает всё сам).
  # --------------------------------------------------------------------------
  loadPresets =
    dir:
    let
      entries = lib.filterAttrs (
        fname: ftype:
        ftype == "regular"
        && lib.hasSuffix ".nix" fname
        && !(lib.hasPrefix "_" fname)
        && fname != "default.nix"
      ) (builtins.readDir dir);
    in
    lib.mapAttrs' (fname: _: {
      name = lib.removeSuffix ".nix" fname;
      value = import (dir + "/${fname}");
    }) entries;
}
