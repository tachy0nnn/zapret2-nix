# YouTube: TLS ClientHello (TCP/443) + QUIC (UDP/443).
#
# Стратегия взята из апстримного config.default zapret2 и сужена хостлистом,
# чтобы не задевать посторонний трафик.
{
  description = "YouTube и googlevideo: TLS ClientHello + QUIC";

  meta = {
    lastVerified = "2026-07-27";
    reference = "https://github.com/bol-van/zapret2 (config.default)";
  };

  hostlist = [
    "youtube.com"
    "youtu.be"
    "googlevideo.com"
    "ytimg.com"
    "ggpht.com"
    "youtubei.googleapis.com"
    "yt3.ggpht.com"
    "jnn-pa.googleapis.com"
  ];

  profiles = [
    {
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
