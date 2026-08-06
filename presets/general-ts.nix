# Универсальный пресет на ВТОРОЙ семье стратегий: одиночный fake с порчей
# TCP-timestamp, без расщепления запроса.
#
# Зачем он есть отдельно от `general`. Все остальные пресеты библиотеки стоят на
# одной семье: fake с `tcp_md5` плюс `multisplit`/`multidisorder`. Если DPI
# провайдера её не пробивает, менять пресеты бессмысленно — они отличаются
# только охватом доменов, а не воздействием. Здесь семья другая:
#
#   • подделка отбраковывается сервером по timestamp (`tcp_ts`), а не по
#     MD5-заголовку — на части каналов md5-опция срезается по дороге, и тогда
#     fake доходит до сервера настоящим, ломая соединение вместо обхода;
#   • настоящий запрос НЕ расщепляется. Сплит помогает против DPI, который
#     собирает поток, но мешает там, где промежуточные узлы не любят
#     переупорядоченные сегменты.
#
# Это прямой перевод классики zapret 1.x
# (`--dpi-desync=fake --dpi-desync-fooling=ts --dpi-desync-repeats=6`)
# в синтаксис zapret2. Именно такая строка стоит первой в апстримном примере
# списка стратегий blockcheck2 — то есть семья живая, а не музейная.
{
  description = "Универсальный: одиночный fake с порчей timestamp, без сплита (классика zapret 1.x)";

  meta = {
    lastVerified = null; # семья проверена апстримом, конкретная цепочка — нет
    reference = "https://github.com/bol-van/zapret2 (blockcheck2.d/custom/list_https_tls12.txt)";
  };

  profiles = [
    {
      filter = {
        tcp = "80";
        l7 = [ "http" ];
      };
      payload = [ "http_req" ];
      desync = [ "fake:blob=fake_default_http:tcp_ts=-1000:repeats=6" ];
    }
    {
      name = "tls";
      filter = {
        tcp = "443";
        l7 = [ "tls" ];
      };
      payload = [ "tls_client_hello" ];
      desync = [ "fake:blob=fake_default_tls:tcp_ts=-1000:repeats=6" ];
    }
    {
      name = "quic";
      filter = {
        udp = "443";
        l7 = [ "quic" ];
      };
      payload = [ "quic_initial" ];
      desync = [ "fake:blob=fake_default_quic:repeats=6" ];
    }
  ];
}
