# Discord: текст/картинки (TLS) + голос (UDP, STUN / IP discovery).
#
# Голосовые каналы Discord ходят по UDP на широком диапазоне портов, поэтому
# для них фильтруем не по домену (хостлист там не поможет — трафик идёт на
# голосовые серверы по IP), а по L7-сигнатурам, которые zapret2 умеет узнавать.
{
  description = "Discord: TLS для API/CDN + STUN и IP discovery для голоса";

  meta = {
    lastVerified = "2026-07-27";
    reference = "https://github.com/bol-van/zapret2 docs/manual.md";
  };

  hostlist = [
    "discord.com"
    "discordapp.com"
    "discordapp.net"
    "discord.gg"
    "discord.media"
    "discordcdn.com"
  ];

  profiles = [
    # API, CDN, веб — обычный TLS, сужен хостлистом.
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

    # Голос: STUN и Discord IP discovery. Хостлист выключен намеренно —
    # трафик идёт на голосовые серверы по IP, доменов в нём нет.
    {
      name = "voice";
      filter = {
        udp = "*";
        l7 = [
          "stun"
          "discord"
        ];
      };
      hostlist = false;
      payload = [
        "stun"
        "discord_ip_discovery"
      ];
      desync = [ "fake:blob=fake_default_quic:repeats=2" ];
    }
  ];
}
