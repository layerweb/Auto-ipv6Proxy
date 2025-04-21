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


## 🛠️ Sorun Giderme

- Kurulum sırasında bir hata ile karşılaşırsanız, detaylı bilgi için `install.log` dosyasını inceleyin.
- Sıkça karşılaşılan sorunlar ve çözümler için [Issues](https://github.com/layerweb/Auto-ipv6Proxy/issues) sayfasını ziyaret edebilirsiniz.
- Destek almak için topluluğumuza veya geliştiricilere ulaşabilirsiniz.

## 📝 Katkıda Bulunun

- Hata bildirmek, yeni özellik önermek veya geliştirmeye katkı sağlamak için lütfen bir [Issue](https://github.com/layerweb/Auto-ipv6Proxy/issues) oluşturun.
- Pull request’leriniz memnuniyetle karşılanır! Kod katkısı, dökümantasyon iyileştirmesi veya önerileriniz için katkıda bulunmaktan çekinmeyin.
- Projeye katkı sağlamak isteyen herkes için açık ve şeffaf bir geliştirme süreci yürütülmektedir.

# Gereksinimler

- 🖥️ IPv6 destekli bir X86-64 VDS (KVM önerilir)
- 🔑 Root yetkisine sahip bir kullanıcı
- 📶 /64 IPv6 subnet atanmış olmalı

Youtube: [https://youtu.be/UZfALUON3k8](https://youtu.be/UZfALUON3k8)
  

Tested By [Hetzner](https://hetzner.cloud/?ref=vMPh0SiWfCW3) Cloud Servers & Sponsored By [CsaDigital](https://csadigital.net/).
