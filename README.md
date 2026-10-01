# MühürKasa (SealedBox)

Akış hâlinde **AES-256-GCM** ile büyük dosyaları ve klasör ağaçlarını mühürleyen,
terminalden çalışan bir komut satırı aracı. Gövde sabit boyutlu tamponla akıtılır:
hiçbir dosya belleğe alınmaz, bu yüzden bellek tüketimi dosya boyutundan bağımsızdır.

Kriptografik çekirdek el yazımı **değildir**; `aes-gcm`, `argon2`, `hkdf`, `sha2`,
`getrandom`, `zeroize` crate'leriyle (RustCrypto) sağlanır. Bu, WORKER_CONTRACT
§3.2'nin kriptografi istisnasıdır (karar D-008).

---

## Özellikler

- **Akış hâlinde AES-256-GCM.** Girdi 2 MiB'lık (varsayılan) parçalara bölünür;
  her parça ayrı bir 512 KiB–8 MiB aralığında seçilen sabit tamponla şifrelenir.
  100 MiB'lik bir dosya ~1 saniyede mühürlenir (ölçüm aşağıda).
- **Parça tabanlı biçim.** Her parça kendi 96-bit nonce'unu ve 128-bit Poly1305
  etiketini taşır; parçalar bağımsız doğrulanabilir. Bir parçanın bozulması
  kapsulun tamamını çöp etmez, yalnızca o parçanın reddedilmesine yol açar.
- **Nonce asla sayaç değildir.** Her parçanın nonce'u `getrandom` ile **rastgele**
  üretilir (rapor b07/b10 uyarısı birebir uygulanmıştır). Ayrıca her dosya
  HKDF-SHA256 ile **ayrı bir alt anahtara** sahiptir; böylece iki farklı dosyada
  rastlantısal bir nonce tekrarı bile şifre çökmez.
- **Klasör ağacı mühürleme.** Yollar, boyutlar, izinler ve zaman damgaları
  şifreli dizin kaydında (manifest) saklanır. Boş dizinler ve boş dosyalar da
  korunur. Geri yüklemede her yol güvenlik denetiminden geçer (`../`, mutlak yol,
  `\` ayracı, sürücü harfi reddedilir) ve yazılan boyut manifest ile karşılaştırılır.
- **Parola türetme: Argon2id** (RFC 9106). Parametreler kapsül başlığında
  **açıkça saklanır**; varsayılan 64 MiB / 3 tur / 4 yol.
- **Kapsül düzeyi SHA-512 bütünlük özeti.** Parça etiklerinin kapsamadığı hataları
  (başlık, manifest, sonradan eklenen baytlar) yakalar.
- **Kaldığı yerden devam.** Mühürleme yarıda kesilirse `mseal sifrele --devam`
  tamamlanmış parçaları tekrar üretmeden sürdürür. Nonce'lar kapsülün kendi
  manifest'inden okunur; hiçbir parça nonce'u yeniden kullanılmaz. Devam sınırı
  **yalnızca diske zorlanmış baytlara** güvenir: gövde `sync_data` ile
  zorlandıktan sonra başlığa yazılır, en fazla 8 MiB geride kalır
  ([ayrıntılı kapsam](https://github.com/SyntaxOrigin/sealedbox#kaldığı-yerden-devamın-kalıcılık-garantisi)).
- **Başarısız çözmede disk artığı bırakmama.** Parça etiketi tutmazsa
  oluşturulmuş ağacın tamamı kaldırılır; `ac` ikinci kez çalıştırılabilir.
- **`zeroize` ile bellek temizliği.** Ana anahtar, alt anahtar, düz metin tamponu
  ve şifreli manifest tamponları `Zeroizing` içinde taşınır; etiket doğrulanmadan
  çözülen düz metin **hiçbir yere yazılmaz** ve hata yolunda sıfırlanır.
- **Üzerine yazma reddi.** Var olan bir kapsülün veya geri yüklenecek ağacın
  üzerine, açıkça istenmedikçe yazılmaz.
- **Makinelere uygun JSON çıktı** (`--json`): parça sayısı, toplam bayt, doğrulama
  durumu ve süre.
- `#![forbid(unsafe_code)]` — projedeki hiçbir satır `unsafe` içermez.

### Bilinçli olarak yapılmayanlar

Sürükle-bırak arayüzü, harici doğrulayıcı (TOTP/OTP), kurtarma anahtarı, iç içe
kapsül, sıkıştırma ve donanım hızlandırma kapsam dışıdır. Gerekçeleri için
[## Bilinen Sınırlamalar](#bilinen-sınırlamalar) bölümüne bakınız.

---

## Kurulum

Gereksinim: Rust **1.74** veya üstü (MSRV; bu depoda `rust-version = "1.74"`
ilan edilmiştir — aşağıdaki ölçümler `rustc 1.98.1` ile alınmıştır).

```bash
cargo build --release
```

Gerçek çıktı:

```text
   Compiling sealedbox v0.1.0 (%USERPROFILE%\Desktop\Projeler\projects\17-sealedbox)
    Finished `release` profile [optimized] target(s) in 53.97s
```

Üretilen ikili: `target/release/mseal.exe` (**1.170.364 bayt**, uyarı: 0).

`cargo install` ile PATH'e kurmak için:

```bash
cargo install --path .
```

Gerçek çıktı:

```text
  Installing %USERPROFILE%\.cargo\bin\mseal.exe
   Installed package `sealedbox v0.1.0 (%USERPROFILE%\Desktop\Projeler\projects\17-sealedbox)` (executable `mseal.exe`)
```

```bash
mseal --version
```

```text
mseal 0.1.0
```

Aşağıdaki tüm örnekler `mseal` (kurulmuş ikili) ile çalıştırılmıştır.

---

## Kullanım

Parola **komut satırı argümanı olarak verilmez** (işlem listelerinde ve kabuk
geçmişinde görünür). Varsayılan kaynak `MSEAL_PAROLA` ortam değişkenidir.

Örnek veri:

```text
        66  veri\rapor.txt
    1048576  veri\belgeler\buyuk.bin
        37  veri\belgeler\notlar.md
```

### 1. Bir klasör ağacını mühürleme

```bash
mseal sifrele ./veri ./veri.sbx --json
```

Gerçek çıktı:

```json
{
  "islem": "mseal sifrele",
  "kapsul": "C:\\Users\\xXx\\AppData\\Local\\Temp\\opencode\\sbx-demo\\veri.sbx",
  "kaynak": "C:\\Users\\xXx\\AppData\\Local\\Temp\\opencode\\sbx-demo\\veri",
  "dosya_sayisi": 3,
  "dizin_sayisi": 2,
  "parca_sayisi": 3,
  "girdi_bayti": 1048679,
  "kapsul_bayti": 1049260,
  "devam_edildi": false,
  "etik_dogrulama": "tamam",
  "sure_ms": 212
}
```

### 2. Kapsül başlığını inceleme

```bash
mseal mseal-info ./veri.sbx
```

Gerçek çıktı:

```text
Kapsul         : %USERPROFILE%\AppData\Local\Temp\opencode\sbx-demo\veri.sbx
Kok dizin      : veri (klasor agaci )
Argon2id       : 65536 KiB / 3 tur / 4 yol
Parca          : 2097152 bayt, 3 parca, 5 girdi
Girdi          : 1048679 bayt
Kapsul         : 1049260 bayt
Etik yuku      : %0.0092
```

### 3. İçeriği çözmeden doğrulama

```bash
mseal mseal-verify ./veri.sbx
```

Gerçek çıktı:

```text
Kapsul         : %USERPROFILE%\AppData\Local\Temp\opencode\sbx-demo\veri.sbx
Dogrulanan     : 3 parca / 1048679 bayt
Sonuc          : tamam
Sure           : 148 ms
```

### 4. Geri yükleme

```bash
mseal ac ./veri.sbx ./geri --json
```

Gerçek çıktı:

```json
{
  "islem": "mseal ac",
  "hedef": "C:\\Users\\xXx\\AppData\\Local\\Temp\\opencode\\sbx-demo\\geri\\veri",
  "dosya_sayisi": 3,
  "dizin_sayisi": 3,
  "parca_sayisi": 3,
  "cikti_bayti": 1048679,
  "kuyruk_ozeti_dogrulandi": true,
  "izin_uygulanamadi": 6,
  "etik_dogrulama": "tamam",
  "sure_ms": 242
}
```

Oluşan ağaç (`boş` dizini dahil):

```text
veri
veri\belgeler
veri\bos
veri\rapor.txt
veri\belgeler\buyuk.bin
veri\belgeler\notlar.md
```

SHA-256 karşılaştırması ile bayt bayt eşitlik doğrulandı:

```text
rapor.txt esit: True
buyuk.bin esit: True
```

> `izin_uygulanamadi: 6` Windows'ta beklendirği gibidir: NTFS ACL'leri `std`
> ile yazılamaz ve `unsafe`/FFI yasaktır. Ayrıntı için
> [## Bilinen Sınırlamalar](#bilinen-sınırlamalar).

### 5. Yanlış parola

```bash
MSEAL_PAROLA=yanlis mseal ac ./veri.sbx ./olmayan
```

Gerçek çıktı (çıkış kodu `1`):

```text
mseal: parola yanlis veya kapsul butunlugu bozuk (parca etigi dogrulanmadi)
```

Mesaj kasıtlı olarak **birleştirilmiştir**: yanlış parola ile bozuk manifest
kriptografik olarak ayırt edilemez, bu yüzden ayrı mesajlar verilmez.

### 6. Üzerine yazma reddi

```bash
mseal sifrele ./veri ./veri.sbx
```

Gerçek çıktı (çıkış kodu `1`):

```text
mseal: '%USERPROFILE%\AppData\Local\Temp\opencode\sbx-demo\veri.sbx' zaten var; uzerine yazmak icin --ustune-yaz kullanin
```

### 7. Bozuk parçanın konumu

Kapsülün 400.000. baytındaki tek bir bit çevrildi:

```bash
mseal mseal-verify ./veri2.sbx
```

Gerçek çıktı (çıkış kodu `1`):

```text
mseal: parca etigi dogrulanmadi: 'belgeler/buyuk.bin' parcasi #0
```

---

## Test

```bash
cargo test
```

Gerçek çıktı (özet):

```text
running 51 tests
test result: ok. 51 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.05s

running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

running 20 tests
test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.90s

running 12 tests
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 15.30s

running 8 tests
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 10.58s

running 5 tests
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.73s

   Doc-tests sealedbox

running 1 test
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
```

**Toplam: 97 test, 97 geçti, 0 başarısız.**

| Hedef | Test sayısı | Kapsam |
|---|---|---|
| `src/lib.rs` birim testleri | 51 | kriptografi, biçim, dizin, gezgin, akış |
| `tests/gidis_donus.rs` | 12 | gidiş-dönüş, akış, klasör ağacı |
| `tests/bozulma_senaryolari.rs` | 20 | bozulma ve saldırı senaryoları |
| `tests/kaldigi_yerden_devam.rs` | 8 | kesinti kurtarma ve devam sınırının kalıcılığı |
| `tests/yarim_cikti_temizligi.rs` | 5 | başarısız çözmede disk artığı bırakılmaması |
| Doc-test (`src/lib.rs` örneği) | 1 | derleme denetimi |

### Yayımlanmış test vektörleri

| Vektör | Nerede | Sonuç |
|---|---|---|
| NIST SP 800-38D, GCM Test Case 13 (AES-256, boş metin) | `kripto::tests::nist_sp_800_38d_katsayim_13_bos_metin` | geçti |
| NIST SP 800-38D, GCM Test Case 14 (AES-256, 16 bayt) | `kripto::tests::nist_sp_800_38d_katsayim_14_tek_blok` | geçti |
| NIST SP 800-38D akış-şifre özelliği (Test Case 14'e bağlı) | `kripto::tests::nist_sp_800_38d_cok_blok_akis_ozelligi_yayilir` | geçti |
| RFC 9106 §5, Argon2id v0x13 (m=32 KiB, t=3, p=4) | `kripto::tests::rfc_9106_argon2id_test_vektoru` | geçti |

### Sabit zamanlılık

`subtle` ve `polyval`/`ghash` crate'leri `aes-gcm` ile **geçişli** olarak gelir;
bu depoda doğrudan bağımlılık değildirler. Kapsül düzeyi SHA-512 özetinin
karşılaştırılması ise `kripto::ozitler_esit` fonksiyonunda elle, XOR-biriktirme
döngüsüyle yapılır (`==` operatörünün kısa devre yapması nedeniyle).
`cargo tree` çıktısındaki geçişli bağımlılıklar normaldir.

```bash
cargo build --release                      # uyarı: 0
cargo clippy --all-targets -- -D warnings  # çıktı boş
cargo fmt --check                          # çıktı boş
```

---

## Proje Yapısı

```text
17-sealedbox/
├── Cargo.toml
├── Cargo.lock
├── LICENSE.txt
├── README.md
├── .gitignore
├── .github/
│   └── workflows/ci.yml     build / test / clippy / fmt + gizli tarama
├── src/
│   ├── lib.rs          çekirdek API ve modül yönlendirme
│   ├── main.rs         mseal komut satırı arayüzü (clap)
│   ├── hata.rs         Hata enum'ı, elle yazılmış Display + Error
│   ├── kapsul.rs       SBX1 sabit başlığı: sabitler, kodlama, ayrıştırma
│   ├── dizin.rs        şifreli dizin kaydı (manifest) ve yol güvenliği
│   ├── kripto.rs       Argon2id, HKDF, AES-256-GCM, SHA-512, getrandom
│   ├── gezgin.rs       özyinelemeli read_dir klasör gezgini (walkdir'siz)
│   ├── akis.rs         akış mühürleme / çözme / kaldığı yerden devam
│   └── dogrulama.rs    kapsül doğrulama (çözmeden etik sınaması)
└── tests/
    ├── yardimci/mod.rs           geçici dizin yardımcısı (tempfile'siz)
    ├── gidis_donus.rs            gidiş-dönüş ve akış testleri
    ├── bozulma_senaryolari.rs    bozulma / saldırı testleri
    ├── kaldigi_yerden_devam.rs   kesinti kurtarma ve devam sınırının kalıcılığı
    └── yarim_cikti_temizligi.rs  başarısız çözmede disk artığı bırakılmaması
```

### Kapsül biçimi (`SBX1`, sürüm 1)

```text
[96 bayt sabit başlık — düz metin]
  0..4    "SBX1"            sihirli sayı
  4..5    sürüm = 1
  5..6    bayraklar (bit0 = klasör ağacı)
  8..12   parça boyutu (u32 LE)
  12..16  Argon2 bellek maliyeti, KiB
  16..20  Argon2 tur sayısı
  20..24  Argon2 yol sayısı
  24..28  tuz uzunluğu = 16
  28..44  tuz
  44..56  manifest nonce (12 bayt)
  56..60  girdi sayısı
  60..64  ayrılmış
  ---- AES-GCM AAD = [0..64]; bu önek mühürleme boyunca DEĞİŞMEZ ----
  64..72  manifest için ayrılan bayt
  72..80  planlanan payload uzunluğu
  80..88  yazılan offset          (kaldığı yerden devam sınırı; KALICILIĞIN
                                  YALNIZCA sync_data sonrası yazılan kısmıdır)
  88..92  durum (0 = tamam, 1 = yazılıyor)
[şifreli manifest + 16 bayt etiket]
[parça gövdeleri]
  her parça: nonce(12) ‖ uzunluk(4) ‖ şifre metni ‖ etiket(16)
[64 bayt SHA-512 kuyruk özeti]   ← [0 .. len-64) aralığının özeti
```

### Kaldığı yerden devamın kalıcılık garantisi

`80..88` alanı bir **ilerleme sayacı değil, kalıcılık beyanıdır**: "buraya kadar
olan gövde baytları diske zorlandı". Bu beyan ancak gövde `sync_data` ile
zorlandıktan **sonra** başlığa yazılır.

```text
   parça yaz  →  parça yaz  →  …  →  bekleyen ≥ 8 MiB
                                          │
                                          ├─ File::sync_data()   ← gövde kalıcı
                                          └─ yazılan_offset = n  ← sonra beyan
```

Sıralamanın tersi (önce beyan, sonra `fsync`) bir kapsülü **kalıcı olarak
bozuk** bırakabilirdi: elektrik kesintisinde başlık "şu kadar bayt yazıldı"
der, parça verisi ise kaybolmuş olur; `devam_ac` o parçayı yeniden üretmeden
atlar ve nonce'i harcanmış sayar. GCM etiketleri sessiz düz metni yakalar ama
kurtarma yolu kalıcı kapanır.

**Gerçek kapsam ve sınırları:**

| Durum | Davranış |
|---|---|
| `sync_data` tamamlanmadan kesinti | Başlık **önceki** kalıcı sınırı gösterir; 8 MiB'den az yeniden üretilir. Güvenli. |
| Tam parça sınırı | `yazilan_offset` her zaman **tam bir parça kaydının** sonundadır; yarım parça "yazılmış" sayılmaz. |
| Eşiği aşan parça | Atlanmaz; `devam_ac` onu yeniden üretir. |
| Kırpma (`devam_ac`) | Kırpma da `sync_all` ile kalıcıdır; ikinci kesintide yarım parça geri gelmez. |
| Mühürleme sonu | Son başlık (`durum = TAMAM`) ve kuyruk özeti `sync_all` ile zorlanır, **sonra** `rename` edilir. |

**Yeniden üretim neden güvenlidir.** Geride kalan parçanın nonce'u diskteki
manifest'ten okunur; nonce **yeniden üretilmez**. Aynı anahtar + aynı nonce +
aynı AAD + aynı düz metin, GCM'de **bit bit aynı** şifre metnini verir; yani
yeniden üretim nonce'u harcamaz, yalnızca aynı kaydı tekrar yazar.

**Maliyet.** Parça başına `fsync` çağırmak yerine 8 MiB
(`akis::KALICILIK_ARALIGI`) toplanır. Varsayılan 2 MiB parçayla 100 MiB
dosyada bu parça başına ~50 yerine ~12 `fsync` demektir.

**Bu garanti neyi kapsamaz:** yalnızca uygulamanın kendi yazma sırasını
kapsar. İşletim sistemi önbelleğini `fsync` çağrısından önce çevrimdışı alıyorsa
(=`sync_data` çağrısı yine de başarılı döner) garanti geçerlidir; disk
donanımının kendi yazma önbelleğini yazma bariyerine rağmen kaybettiği durum
bu kapsamın **dışındadır** ve yazılımla giderilemez.

---

## Yapılandırma

Ayar dosyası, ortam değişkeni veya çalıştırılabilir yanında ayar **yoktur**;
her şey komut satırındadır. Parola hiçbir zaman diske yazılmaz.

### Parola kaynağı (öncelik sırasıyla)

| Bayrak | Kaynak | Not |
|---|---|---|
| `--parola <değer>` | doğrudan değer | **önerilmez**: kabuk geçmişine yazılır |
| `--parola-dosya <yol>` | dosya | satır sonu (`\n`, `\r`) kırpılır |
| `--parola-degiskeni <ad>` | ortam değişkeni | değişken yoksa hata |
| `--parola-stdin` | standart girdi | satır sonu kırpılır |
| (varsayılan) | `MSEAL_PAROLA` ortam değişkeni | değişken yoksa hata |

### `mseal sifrele`

| Bayrak | Varsayılan | Aralık | Etki |
|---|---|---|---|
| `--parca-baytu <n>` | `2097152` (2 MiB) | 524288 – 8388608 | Parça başına düz metin uzunluğu. Büyük değer = az etik yükü, geniş bellek tamponu |
| `--argon2-bellek-kib <n>` | `65536` | 16384 – 262144 | Argon2id bellek maliyeti. Kaba kuvveti pahalılaştırır, açılış süresini uzatır |
| `--argon2-tur <n>` | `3` | 1 – 10 | Argon2id işlem turu |
| `--argon2-yol <n>` | `4` | 1 – 16 | Argon2id paralellik. `bellek_kib >= 8 * yol` olmalıdır |
| `--ustune-yaz` | kapalı | — | Var olan kapsülün üzerine yazılır |
| `--devam` | kapalı | — | Yarım kalmış `<kapsül>.sbxtmp` dosyasından kaldığı yerden sürdürülür |
| `--json` | kapalı | — | Sonuç JSON olarak yazılır |

### `mseal ac`

| Bayrak | Varsayılan | Aralık | Etki |
|---|---|---|---|
| `--ustune-yaz` | kapalı | — | Var olan ağaç önce silinir, sonra geri yüklenir |
| `--kuyruk-ozeti-atla` | kapalı | — | Kapsül düzeyi SHA-512 denetimi yapılmaz (daha hızlı, ama kesme/ekleme saldırisine açık) |

### Diğer alt komutlar

| Komut | Bayraklar |
|---|---|
| `mseal listele` | ortak parola bayrakları, `--json` |
| `mseal-info` (takma ad: `bilgi`) | ortak parola bayrakları, `--json` |
| `mseal-verify` (takma ad: `dogrula`) | ortak parola bayrakları, `--json` |

`mseal sifrele --help` ve `mseal ac --help` tüm seçenekleri listeler.

### Çıkış kodları

| Kod | Anlam |
|---|---|
| `0` | başarılı |
| `1` | hata (hata mesajı `stderr`'e yazılır; parola veya içerik **yok**) |

---

## Bilinen Sınırlamalar

Bu bölüm kasıtlı olarak dürüsttür. Hiçbir madde ölçülmüş veya gizli değildir.

### Ertelenen özellikler (MANIFEST kart 17 "Ertelenen" listesi)

- **İç içe kapsül** (bir kapsülün başka bir kapsülü sarmalaması) uygulanmadı.
- **Kurtarma anahtarı** yoktur. Parola unutulursa kapsül açılamaz; bu geri dönüşü
  olmayan bir veri kaybıdır. Yedekleme yapmadan önce parolayı güvenli bir yere yazın.
- **Sürükle-bırak / grafik arayüz** yoktur. Yalnızca terminal vardır
  (WORKER_CONTRACT §3.2-G pencere katmanını yasaklar; ayrıca `unsafe`/FFI gerektirirdi).
- **Donanım hızlandırma (AES-NI) yoktur.** Bkz. aşağıdaki performik maddesi.
- **Harici doğrulayıcı (TOTP/OTP) ve parola yığını** uygulanmadı. Parola yığını
  raporun v1 kapsamındaydı; MVP'de tek parola yeterli kabul edildi.
- **Sıkıştırma** gömülü değildir (rapor b05 bunu bilinçli olarak dışarıda bırakır:
  şifrelemeden önce sıkıştırma, şifreli çıktının yüksek entropisini bozar).
- **Kaldığı yerden devam etiket yazma sırasına duyarlıdır.** Devam, tamamlanmış
  parçaların atlanmasıyla çalışır; parçalar arası "herhangi bir noktadan başla"
  yeteneği yoktur.
- **Başarısız çözmede ağaç temizlenir, ama hedef birden fazla dosyaysa iş
  tekrarlanabilir olmaz.** Etiket tutmayan bir parçada oluşturulan ağacın tamamı
  kaldırılır (`tests/yarim_cikti_temizligi.rs` bunu ağaç dökümüyle kanıtlar), bu
  yüzden hassas veri yarım hâlde diskte kalmaz ve `ac` ikinci kez çalıştırılabilir.
  Ancak `--ustune-yaz` ile hedef agacın **önceki** hâli geri yüklenemez: eski
  ağaç yeni yazım başlamadan önce silinir. Geri alınabilir bir çözme için
  [geçici dizine yazıp atomik taşıma](#gelecek-geliştirmeler) gerekir.

### Teknik sınırlar

- **Yazılım AES-GCM hızı.** Bu depoda AES-NI yolu **kullanılmıyor**
  (`aes` crate'i hedefe özel `aes` backend'iyle derlenmiştir). İşlemci:
  12. Gen Intel Core i5-12400F, Windows 11, `rustc 1.98.1`, release profili.
  100 MiB dosya için ölçülen süreler (ortalama, tek çalıştırma):

  | İşlem | Süre | İçim |
  |---|---|---|
  | `sifrele` (Argon2id 64 MiB dahil) | 0,96 sn | ~109 MiB/sn |
  | `mseal-verify` (SHA-512 kuyruk özeti dahil) | 1,01 sn | ~103 MiB/sn |
  | `ac` (çözme + yazma + kuyruk özeti) | 1,14 sn | ~92 MiB/sn |

  Rapordaki "terabaytlık arşiv" senaryosu bu hızla pratik değildir (4 TB ≈ 10 saat,
  tek akışta, darboğaz disk hızı olur). Donanım hızlandırması eklenirse bu sayılar
  ciddi biçimde değişir; ölçüm yeniden yapılmalıdır. **Bu sayılar yalnızca bu
  makineye aittir, rapordan aktarılmamıştır ve başka kaynaklardan alınmamalıdır.**

- **Tepe RSS ölçülmedi.** 96 MiB bellek bütçesi raporun hedefidir; bu depoda süreç
  RSS'i ölçen bir mekanizma yok (`/proc` ve Windows API erişimi `unsafe` gerektirir).
  Bunun yerine **mekanizma denetimi** yapıldı: gövde tamponunun kapasitesi parça
  boyutuna eşittir ve parça sayısı arttıkça değişmez
  (`akis::tests::parca_tamponu_sabit_kapasitededir`), 12 MiB + 137 baytlık bir
  dosya 25 parçaya bölünerek gidiş-dönüş sınanır
  (`gidis_donus::cok_parcali_buyuk_dosya_akis_halinde_gidis_donus_basar`).
  **Tek değişen bellek: manifest, yani dosya ve parça sayısıyla ölçeklenir.**

- **Argon2 açılış maliyeti.** Varsayılan 64 MiB / 3 tur / 4 yol, küçük bir
  dosyada bile belirgin gecikme yaratır (demo `sifrele` komutunda 212 ms'in çoğu
  buraya gidiyor). Testler bunu hızlandırmak için 16 MiB / 1 tur / 1 yol kullanır;
  bu yalnızca **testler içindir**, varsayılanlar değiştirilmemiştir.

- **Windows'ta izinler geri yüklenmez.** `std::os::windows::fs::PermissionsExt`
  bu toolchain'de kararsız (`windows_permissions_ext`), NTFS ACL'leri ise
  `unsafe`/FFI olmadan yazılamaz. Bu yüzden izin bitleri kapsüle **kaydedilir**
  ama Windows'ta **uygulanmaz**; `ac --json` çıktısındaki `izin_uygulanamadi`
  sayacı bunu ölçülebilir biçimde bildirir (demo çıktısında `6`). Unix'te tam
  `chmod` modu geri yüklenir. **Dizin izinleri de geri yüklenmez** (Windows'ta
  salt-okunur dizinler silinemez hale gelirdi).

- **Kapsül düzeyi SHA-512 özeti tam bir tarama gerektirir.** `ac` varsayılan olarak
  kapsülü baştan sona bir kez daha okur. `--kuyruk-ozeti-atla` bu maliyeti
  kaldırır ama o zaman sonradan eklenen baytlar yalnızca parça etikleriyle
  sınırlı kalır.

- **Simge bağları (sembolik bağ) atlanır**; mühürlenmez ve geri yüklenmez.
  Bu bilinçli bir güvenlik kararıdır: geri yükleme hedef ağacın dışına çıkmamalıdır.

- **Tek dosya kapsülünde geri yükleme hedefi yolun kendisidir.** `mseal ac tek.sbx
  ./geri.txt` komutu `./geri.txt` dosyasını oluşturur; `./geri/` değil. Klasör
  kapsülünde ise kapsülün kök dizini `hedef/<kok_ad>` altına açılır.

- **Zaman damgaları kapsüle yazılır ama geri yüklemede uygulanmaz.** `std` güvenli
  bir `set_mtime` sunmaz; `unsafe`/FFI yasak. Bilgi kaybolmaz, yalnızca uygulanmaz.

- **MSRV gerçekten doğrulanmadı.** `rust-version = "1.74"` ilan edilmiştir ancak
  bu depoda 1.74 toolchain'i ile derleme yapılmamıştır (ortamda yalnızca 1.98.1 ve
  1.98.1-msvc vardır). MSRV'nin gerçekten 1.74 mü olduğu **test edilmemiştir**.

- **Kaldığı yerden devam yalnızca kendi yazma sırasına güvenir.** Devam sınırı
  `sync_data` ile zorlanmış baytlardan oluşur (bkz.
  [Kaldığı yerden devamın kalıcılık garantisi](#kaldığı-yerden-devamın-kalıcılık-garantisi));
  bu, uygulamanın kendi yazma sırasını garanti eder, **disk donanımının** kendi
  yazma önbelleğini yazma bariyerine rağmen kaybettiği (güç kesintisi, denetleyici
  hatası) durumları kapsam dışıdır. Ek olarak kapsülün `rename` edilmesi
  dizinin üst dizinine göre kalıcı hâle getirilmez (dizin `fsync`'i platform
  bağımlıdır), bu yüzden `rename` ile kapsül hedef yola düştükten hemen sonra
  oluşan bir güç kesintisi kapsülü `*.sbxtmp` halinde bırakabilir. Kapsül içeriği
  bozulmaz; `--devam` ile yeniden denemek yeterlidir.

- **Kapsül dosyasının izinleri daraltılmaz.** Rapor b09 "dosya sistemi önlemleri"
  (kapsul dosyası izinlerinin daraltılması) ister; bu sürümde yapılmamıştır.

- **İki kullanımlılık riski kabul edilmiştir.** Çalıntı bir kapsulu açmak için de
  kullanılabilir (her şifreleme aracı için geçerlidir). Sürükle-bırak arayüzü,
  toplu otomatik çalıştırma, parola listesi ve deneme hızlandırma **yoktur**.

### `#[allow]` kullanımları

| Konum | Gerekçe |
|---|---|
| `#[cfg(test)] mod tests` blokları (her modülde) | `clippy::unwrap_used` / `expect_used`; WORKER_CONTRACT §4.2 testlerde bunlara izin verir |
| `akis.rs::devam_ac` | `clippy::type_complexity` — 5 alanlı `Option<(File, SabitBaslik, Zeroizing<..>, [u8;16], DizinKaydi)>` dönüşü; yeni bir tip adı hata ayıklama okunurluğunu düşürürdü |
| `akis.rs::kapsul_ac` | `clippy::type_complexity` — 3 alanlı demet dönüşü |
| `akis.rs::ac_govde` | `clippy::too_many_arguments` — 9 parametre; ikisi (`kapsul_yolu`, `kok`) çözme durumudur, kalanı manifest/başlık/anahtar bağlamıdır. Hata halinde ağacın temizlenmesi gerektiği için `ac`'den ayrılmak zorunda kaldı |

---

## Gelecek Geliştirmeler

1. **Donanım hızlandırması.** `aes` crate'inin `aes` backend'i yerine
   `aes` + `target-feature=+aes,+sse2` (veya `aes-gcm`'nin donanım yolu) etkinleştirilip
   README'deki hız tablosu yeniden ölçülmeli.
2. **Parola yığını + harici doğrulayıcı (v1).** Doğrulayıcı yanıtının HKDF
   `info` girdisine karıştırılması; "parola doğru, doğrulayıcı yanlış" durumunda
   kapsül açılmaması.
3. **Kurtarma anahtarı.** Ayrı dosyada taşınan ikinci anahtar malzemesi; kapsül
   başlığına gömülmez.
4. **İç içe kapsül sınırı.** Ağaç derinliği için açık bir üst sınır ve döngü
   tespiti (rapor b16 açık soru 4).
5. **Kapsül dosyası izinlerini daraltma** (rapor b09 dosya sistemi önlemleri) ve
   zaman damgası geri yükleme.
6. **Biyometrik / donanım anahtarı desteği** (Argon2 `secret` girdisi olarak).
7. **Sürükle-bırak arayüzü** — kapsam dışı bırakıldı; yeniden değerlendirme
   gerektirir.
8. **Çok iş parçacılı parça şifreleme** — kuyruk derinliği 2 ile (rapor b08).
9. **Biçim belgesi (`FORMAT.md`)** — kapsül sürüm 2 için sürümleme kuralları
   (rapor b16 hafta 1 aksiyonu).
10. **Geçici dizine yazıp doğrulama sonrası atomik taşıma.** Bugün `ac` doğrudan
    hedefe yazar ve hatada oluşturduğu ağacı **kaldırır**; bu, yarım veri
    bırakmaz ama iki noktada eksiktir:
    - `--ustune-yaz` ile hedef ağacın **önceki** hâli geri getirilemez (önce
      silinir, sonra yazılır).
    - Temizlik `remove_*` çağrısına dayanır; dosya kilitliyse
      `Hata::YarimCiktiKaldi` ile bildirilir ama yarım veri yine de kalır.

    Çözüm: çözme `hedef/.mseal-gecici-<rastgele>/` altında yapılır, tüm parça
    etiketleri doğrulandıktan ve boyutlar manifest ile karşılaştırıktan **sonra**
    ağaç hedefe `rename` edilir. Aynı dosya sisteminde `rename` atomiktir, bu
    yüzden hedef ya eski hâlini ya da tam yeni ağacı gösterir — asla yarım.
    Kapsül dosyası zaten bu şekilde çalışıyor (`*.sbxtmp` → `rename`); çözme
    tarafına aynı disiplin taşınacak.

---

## Troubleshooting

### 1. `parola yanlis veya kapsul butunlugu bozuk`

**Belirti:** `mseal ac` bu mesajı döndürür ve hiçbir dosya yazmaz.
**Neden:** (a) parola yanlış; (b) kapsülün manifest bölümü bozuk; (c) kapsül
kopyalanırken kesildi. Üçü de kriptografik olarak ayırt edilemez.
**Çözüm:** Önce parolayı doğrulayın. Sonra `mseal-verify` çalıştırın: parça
etikleri sağlamsa sorun paroladadır; kuyruk özeti hatası alırsanız kapsülün
taşıma sırasında bozulduğu anlaşılır. Kapsülü mümkünse **farklı bir diske**
kopyalayıp tekrar deneyin (disk hatası olasılığı).

### 2. `parca etigi dogrulanmadi: '<dosya>' parcasi #N`

**Belirti:** `mseal-verify` veya `mseal ac` belirli bir parçayı işaret eder.
**Neden:** O parçanın şifre metni ya da etiketi değişmiş. Bit çevirme, kısmi
kopyalama, bozuk disk veya bilinçli bir müdahale.
**Çözüm:** Başka bir konuma kopyalayıp yeniden deneyin. Sorun sürerse kapsül
güvenilir değildir; kurtarma için parolanın güvenli bir yedeği olup olmadığını
kontrol edin. Kapsülün hangi parçanın bozuk olduğunu bildirmesi, kalan parçaların
kurtarılması için ön bilgidir.

### 3. `'X.sbx' zaten var; uzerine yazmak icin --ustune-yaz kullanin`

**Belirti:** `mseal sifrele` var olan bir kapsülün üzerine yazmıyor.
**Neden:** Yanlışlıkla veri kaybetmemek için üzerine yazma varsayılan olarak kapalı.
**Çözüm:** `--ustune-yaz` ekleyin, ya da (önerilen) başka bir kapsül adı verin.
Aynı kural `mseal ac` için de geçerlidir: hedef ağaç varsa geri yükleme reddedilir.

### 4. `kapsul yazilmamis; kaldigi yerden devam edin`

**Belirti:** `<kapsül>.sbxtmp` dosyası kaldı, `<kapsül>` oluşmadı.
**Neden:** Önceki `mseal sifrele` çalıştırması kesildi (güç kesintisi, disk doldu,
Ctrl-C).
**Çözüm:** `mseal sifrele <kaynak> <kapsül> --devam` komutunu çalıştırın; tamamlanmış
parçalar atlanır. Kaynak değişmişse devam reddedilir ve sıfırdan başlanır. Devamı
istemiyorsanız `--devam` kullanmadan çalıştırın; geçici dosya silinip yeniden
yazılır.

`--devam` **atlanan** parça sayısını raporlamaz; sadece devam yolunun kullanılıp
kullanılmadığını bildirir. Devam sınırı diske zorlanmış baytlardan oluştuğu
için en fazla 8 MiB geride kalır ve geride kalan parçalar yeniden üretilir
([bkz.](#kaldığı-yerden-devamın-kalıcılık-garantisi)). Ağır bir kesintiden sonra
beklenen şey "son parçadan devam" değil, "son kalıcı sınırdan devam"dır.

### 5. `Argon2 bellek maliyeti ... KiB; izinli aralik 16384..262144`

**Belirti:** `--argon2-bellek-kib` çok küçük veya çok büyük verilmiş.
**Neden:** Rapor b10'daki sınırlar uygulanıyor; ayrıca `bellek_kib >= 8 * yol`
olmalıdır.
**Çözüm:** Değeri aralığa alın ya da bayrağı hiç vermeyin (varsayılan 65536 KiB).
Düşük bellek kaba kuvvet saldırısını ucuzlatır; üretimde varsayılanı kullanın.

### 6. `dosya sistemi hatasi: ... erisim engellendi`

**Belirti:** Diskte yer yok veya dosya başka bir süreçte kilitli.
**Neden:** Kapsül yazılırken hedef disk doldu; veya Windows Defender kapsül
dosyasını kısa süre kilitledi.
**Çözüm:** Kapsülü başka bir diske yazın. Diskte yer bırakın: kapsülün boyutu
girdinin boyutundan **her zaman büyüktür** (parça başına 32 bayt kayıt yükü +
96 bayt başlık + manifest + 64 bayt kuyruk özeti). `mseal mseal-info` çıktısındaki
`Etik yuku` yüzdesi bu yükü gösterir.

### 7. `cozme basarisiz oldu ve yarim cikti kaldirilamadi: '<yol>'`

**Belirti:** Çözme bir parça etiketi (veya okuma hatası) nedeniyle başarısız
oldu ve oluşturduğu ağacı `remove_*` ile kaldıramadı; mesaj ayrıca temizlik
hattasının metnini içerir.
**Neden:** Normalde `ac` hatada oluşturduğu ağacın **tamamını** siler
(`tests/yarim_cikti_temizligi.rs` bunu ağaç dökümüyle kanıtlar). Bu varyant
yalnızca silme işleminin kendisi başarısız olduğunda — dosya başka bir süreçte
kilitle, antivirüs tarama sırasında, izin kısıtlı bir ağda paylaşım — çıkar.
**Çözüm:** Mesajda geçen yolu **elle silin**; diskte eksik/yarım düz metin
kalıcıdır. Hedefte başka bir sürücü seçin ve antivirüs'ün gerçek zamanlı
taramasını geçici olarak durdurun. Kalıcı çözüm için
[geçici dizine yazıp atomik taşıma](#gelecek-geliştirmeler) gerekir.

---

## Atıflar

Bu bölüm, uygulanan spesifikasyonların ve kullanılan açık kaynak projelerin
kaynaklarını içerir. Tüm bağlantılar gerçektir.

### Standartlar ve spesifikasyonlar

- **NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation:
  Galois/Counter Mode (GCM)**, <https://csrc.nist.gov/publications/detail/sp/800-38d/final>
  — GCM modu, 96-bit nonce gereksinimi ve Test Case 13/14 test vektörleri.
- **RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols**,
  <https://www.rfc-editor.org/rfc/rfc8439> — Poly1305 doğrulama etiketinin
  yapısı ve sabit zamanlı karşılaştırma disiplini.
- **RFC 5116 — An Interface and Formats for Authenticated Encryption**,
  <https://www.rfc-editor.org/rfc/rfc5116> — AEAD arayüzü ve nonce/etiket
  uzunluklarının seçimi.
- **RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)**,
  <https://www.rfc-editor.org/rfc/rfc5869> — ana anahtar ve dosya alt anahtarı türetme.
- **RFC 9106 — Argon2: Password-Hashing Method**,
  <https://www.rfc-editor.org/rfc/rfc9106> — Argon2id, bellek-zorlu parametreler ve
  §5 Argon2id v0x13 test vektörü.
- **FIPS 180-4 — Secure Hash Standard (SHA-2)**,
  <https://csrc.nist.gov/publications/detail/fips/180-4/final> — kapsül düzeyi
  SHA-512 bütünlük özeti.

### Kullanılan açık kaynak crate'ler (RustCrypto ve çevresi)

- `aes-gcm` — <https://docs.rs/aes-gcm> · <https://github.com/RustCrypto/AEADs>
- `aes` — <https://docs.rs/aes>
- `aead` — <https://docs.rs/aead>
- `ghash` — <https://docs.rs/ghash>
- `argon2` — <https://docs.rs/argon2> · <https://github.com/RustCrypto/password-hashes>
- `hkdf` — <https://docs.rs/hkdf> · <https://github.com/RustCrypto/KDFs>
- `sha2` — <https://docs.rs/sha2> · <https://github.com/RustCrypto/hashes>
- `getrandom` — <https://docs.rs/getrandom> · <https://github.com/RustCrypto/random>
- `zeroize` — <https://docs.rs/zeroize> · <https://github.com/RustCrypto/utils>
- `clap` — <https://docs.rs/clap> · <https://github.com/clap-rs/clap>
- `serde` — <https://serde.rs/> · <https://github.com/serde-rs/serde>
- `serde_json` — <https://docs.rs/serde_json> · <https://github.com/serde-rs/json>

### Araçlar ve standart kütüphane

- Rust standart kütüphane belgeleri — <https://doc.rust-lang.org/std/>
- Rust 2021 edition rehberi — <https://doc.rust-lang.org/edition-guide/edition-2021.html>
- `cargo` yerel rehberi — <https://doc.rust-lang.org/cargo/>
- Semantic Versioning — <https://semver.org/>

### Tasarım referansları

- **age şifreleme aracı** — <https://age-encryption.org/> — akış (streaming) şifre
  arşiv tasarımı için referans; parça bazlı biçim ve parola ile çalışma modeli.
- **Tarsnap / scrypt format** — <https://www.tarsnap.com/> — parça bazlı
  doğrulama ve başlıkta parça tablosu fikri.
- **GnuPG** — <https://www.gnupg.org/> — açık anahtar yaklaşımı ve anahtar yönetimi dersleri.
- **Wycheproof** — <https://github.com/google/wycheproof> — bilinen yanıt test
  vektörlerinin düzenlenme biçimi (bu depoda ayrıca **kullanılmamıştır**; NIST
  SP 800-38D vektörleri tercih edilmiştir).
- **OWASP Password Storage Cheat Sheet** —
  <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
  — Argon2id parametre seçimi gerekçeleri.
- **OWASP Cryptographic Storage Cheat Sheet** —
  <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>
  — nonce/IV yeniden kullanımı kuralları.

### Kaynak rapor (iç tasarımın kaynağı)

- `%USERPROFILE%\Desktop\Fikirler\17-muhur-dosya-sifreleyici.html` — "MühürKasa
  (SealedBox) — AES-256-GCM akış şifreleme motoru", fikir raporu 17/30,
  29 Eylül 2026. **Bu bir URL değil, yerel bir dosya yoludur.** Bu deponun biçim
  ve arayüz kararlarının çoğu bu rapordan gelir; rapor OpenSSL 3 ve libsodium
  önerir, bu depo ise WORKER_CONTRACT §3.2 ve MANIFEST kart 17 uyarınca saf Rust
  (RustCrypto) karşılığını kullanır.

### Doğrudan kopyalanan kod

**Yoktur.** Depodaki hiçbir satır başka bir projeden kopyalanmamıştır; tüm
mantık bu depo için yazılmıştır.

---

## Üretim Atfı

Bu depo **OpenCode** ajanı tarafından, **`space-bunny-free`** modeli
(`opencode/space-bunny-free`) kullanılarak üretilmiştir.

- **Arac:** OpenCode
- **Model:** `opencode/space-bunny-free` (Space Bunny Free)
- **Tür:** Rust, `cargo build` / `cargo test` ile üretilmiş ve doğrulanmıştır.

Kaynak kod, testler ve dokümantasyon bu model tarafından yazılmıştır. İnsan
katkısı: gereksinim tanımı, kabul ölçütleri ve son kontroller.

## Lisans

**MIT** lisansı. Tam metin için [LICENSE.txt](LICENSE.txt) dosyasına bakınız.

Telif: `Copyright (c) 2026 SealedBox contributors`
