# Библиотека пресетов как чистые данные — без модуля и без pkgs.
# Валидация происходит там, где пресеты попадают в опцию (тип presetType).
{ lib }:

(import ../lib {
  inherit lib;
  pkgs = null;
}).loadPresets
  ./.
