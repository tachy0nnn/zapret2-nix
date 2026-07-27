# Универсальный пресет — аналог апстримного NFQWS2_OPT «из коробки».
#
# Покрывает HTTP (80), TLS (443) и QUIC (443/udp) без привязки к доменам:
# применяется ко ВСЕМУ трафику на этих портах. Подходит как отправная точка,
# когда неизвестно, что именно блокируется.
#
# ⚠️ Хостлист пуст намеренно. Это шире по охвату, но и нагрузка выше, и выше
# шанс задеть посторонний ресурс. Если знаешь конкретные домены — возьми
# точечный пресет (youtube/discord) или объяви свой через `extraPresets`.
{
  description = "Универсальный: HTTP + TLS + QUIC, без привязки к доменам";

  meta = {
    lastVerified = "2026-07-27";
    reference = "https://github.com/bol-van/zapret2 (config.default NFQWS2_OPT)";
  };

  profiles = [
    {
      filter = {
        tcp = "80";
        l7 = [ "http" ];
      };
      payload = [ "http_req" ];
      desync = [
        "fake:blob=fake_default_http:tcp_md5"
        "multisplit:pos=method+2"
      ];
    }
    {
      name = "tls";
      filter = {
        tcp = "443";
        l7 = [ "tls" ];
      };
      payload = [ "tls_client_hello" ];
      desync = [
        "fake:blob=fake_default_tls:tcp_md5:tcp_seq=-10000"
        "multidisorder:pos=1,midsld"
      ];
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
