{
  description = "Roblox: TLS ClientHello";

  meta = {
    lastVerified = "2026-11-17";
    reference = "https://github.com/ZenonEl/zapret2-nix";
  };

  hostlist = [
    "roblox.com"
    "rbx.com"
    "rbxcdn.com"
    "robloxusercontent.com"
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
  ];
}
