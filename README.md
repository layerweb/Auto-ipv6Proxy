# 🌍 Otomatik IPv6 Proxy Kurulumu

Sistem yöneticileri ve ağ profesyonellerinin işlerini kolaylaştırmak amacıyla **tek komutla IPv6 proxy** kurulumu yapabilecekleri basit bir script hazırladık. Bu script ile birkaç saniye içinde kendi IPv6 proxy'nizi kurabilir, zaman kaybetmeden kullanıma hazır hale getirebilirsiniz.

## 🚀 Tek Komutla Kurulum

Hiçbir dosyayı elle indirmenize gerek yok. Sadece aşağıdaki komutu terminalinize yapıştırın ve script otomatik olarak kurulumu yönlendirmeleriniz ile tamamlasın:

```bash
curl https://raw.githubusercontent.com/layerweb/Auto-ipv6Proxy/refs/heads/main/install.sh | bash
```

# Script Özellikleri

- ✅ Otomatik 3proxy proxy kurulumu
- ✅ Rastgele IPv6 jenerasyonu (/64 subnet üzerinden)
- ✅ Proxy kullanıcı adı/şifre desteği
- ✅ (Opsiyonel) Whitelist IP Auth Method
- ✅ Universal Linux Desteği
- ✅ Proxy IP listesi otomatik oluşturulur

# Gereksinimler

- 🖥️ IPv6 destekli bir X86-64 VDS (KVM önerilir)
- 🔑 Root yetkisine sahip bir kullanıcı
- 📶 /64 IPv6 subnet atanmış olmalı
  

Tested By [Hetzner](https://hetzner.cloud/?ref=vMPh0SiWfCW3) Cloud Servers & Sponsored By [CsaDigital](https://csadigital.net/).
