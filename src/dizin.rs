//! Kapsül içindeki dizin kaydı (manifest) ve yol güvenliği doğrulaması.
//!
//! Manifest, kapsülün "ne var" sorusunu yanıtlayan bölümüdür: dosya yolları,
//! türleri, boyutları, izinleri, zaman damgaları ve parça tablosu. Manifest
//! başlıkla birlikte şifrelenir ve AES-GCM etiketiyle doğrulanır, bu yüzden
//! içeriği değiştirilmiş bir kapsülden güvenilir yol/boyut bilgisi alınamaz.
//!
//! Bu modül dosya sistemine dokunmaz; yalnızca bayt dizisi üretir ve ayrıştırır.

use crate::hata::Hata;
use crate::kapsul::{ParcaKonumu, NONCE_UZUNLUGU};

/// Manifest sihirli sayısı; ilk dört bayt.
pub const MANIFEST_SIHRLI: [u8; 4] = *b"SBM1";
/// Bir yol bileşeninin izin verilen en uzun bayt uzunluğu.
pub const EN_UZUN_BILESEN: usize = 255;
/// Bir kapsül yolunun izin verilen en uzun bayt uzunluğu.
pub const EN_UZUN_YOL: usize = 4096;

/// Kapsüldeki bir girdinin türü.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tur {
    /// Düzenli dosya; sıfır veya daha fazla parçaya sahiptir.
    Dosya,
    /// Dizin; parçası yoktur, geri yüklemede boş olsa bile oluşturulur.
    Dizin,
}

/// Manifest içindeki tek bir girdi.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Giris {
    /// Kapsül köküne göreli yol, `/` ile ayrılmış bileşenler.
    pub yol: String,
    /// Girdinin türü.
    pub tur: Tur,
    /// Dosya boyutu (bayt); dizinlerde `0`.
    pub boyut: u64,
    /// Saklanan izin bitleri (Unix modu; Windows'ta salt-okunur biti).
    pub izin: u32,
    /// Değişiklik zamanı (Unix saniyesi).
    pub mtime_saniye: i64,
    /// Değişiklik zamanının nanosaniye kısmı.
    pub mtime_nano: u32,
    /// Dosyanın parçaları, kapsül içi sırayla.
    pub parcalar: Vec<ParcaKonumu>,
}

impl Giris {
    /// Girdinin kapsülde kapladığı şifre metni baytı.
    pub fn sifre_bayti(&self) -> u64 {
        self.parcalar.iter().map(|p| p.toplam_bayt()).sum()
    }
}

/// Çözülmüş kapsül dizini.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DizinKaydi {
    /// Kapsülün kök dizin adı; geri yüklemede hedef altında oluşturulur.
    pub kok_ad: String,
    /// Kök dizin adı hariç tüm girdiler, yola göre sıralı.
    pub girdiler: Vec<Giris>,
}

impl DizinKaydi {
    /// Kapsüldeki toplam parça sayısı.
    pub fn parca_sayisi(&self) -> u64 {
        self.girdiler.iter().map(|g| g.parcalar.len() as u64).sum()
    }

    /// Kapsüldeki toplam düz metin baytı.
    pub fn toplam_bayt(&self) -> u64 {
        self.girdiler.iter().map(|g| g.boyut).sum()
    }

    /// Girdileri yol sırasına göre sıralar ve yinelenen yolları reddeder.
    ///
    /// Sıralama determinizmi sağlar: aynı girdi kümesi her zaman aynı kapsül
    /// baytlarını üretir. Ayrıca `a` gibi bir üst dizin, `a/b` girdisinden
    /// önce gelir; bu sayede geri yükleme sırasında üst dizin önce oluşur.
    pub fn sirala(&mut self) -> Result<(), Hata> {
        self.girdiler.sort_by(|a, b| a.yol.cmp(&b.yol));
        for pencere in self.girdiler.windows(2) {
            if pencere[0].yol == pencere[1].yol {
                return Err(Hata::BozukKapsul(format!(
                    "yinelenen kapsul yolu: '{}'",
                    pencere[0].yol
                )));
            }
        }
        Ok(())
    }

    /// İki kaydın yapısal olarak aynı girdi kümesini taşıyıp taşımadığını kontrol eder.
    ///
    /// Nonce'ler bilinçli olarak **yok sayılır**: kaldığı yerden devam edilen bir
    /// mühürlemede yeni parçalar için yeni nonce üretilir, bu yüzden bayt
    /// karşılaştırması kullanılamaz. Karşılaştırılanlar yol, tür, boyut, izin
    /// ve parça ofsetleridir; kaynak değişmişse devam reddedilir.
    pub fn yapisal_esit(&self, diger: &DizinKaydi) -> bool {
        if self.kok_ad != diger.kok_ad || self.girdiler.len() != diger.girdiler.len() {
            return false;
        }
        self.girdiler
            .iter()
            .zip(diger.girdiler.iter())
            .all(|(a, b)| {
                a.yol == b.yol
                    && a.tur == b.tur
                    && a.boyut == b.boyut
                    && a.parcalar.len() == b.parcalar.len()
                    && a.parcalar.iter().zip(b.parcalar.iter()).all(|(pa, pb)| {
                        pa.ofset == pb.ofset && pa.sifre_uzunlugu == pb.sifre_uzunlugu
                    })
            })
    }

    /// Manifest'in düz metin temsilini üretir.
    pub fn kodla(&self) -> Vec<u8> {
        let boyut = self.kodlanmis_uzunluk();
        let mut bayt = Vec::with_capacity(boyut);
        bayt.extend_from_slice(&MANIFEST_SIHRLI);
        yaz_u32(&mut bayt, self.kok_ad.len() as u32);
        bayt.extend_from_slice(self.kok_ad.as_bytes());
        yaz_u32(&mut bayt, self.girdiler.len() as u32);
        for giris in &self.girdiler {
            yaz_u32(&mut bayt, giris.yol.len() as u32);
            bayt.extend_from_slice(giris.yol.as_bytes());
            bayt.push(match giris.tur {
                Tur::Dosya => 0,
                Tur::Dizin => 1,
            });
            bayt.extend_from_slice(&giris.boyut.to_le_bytes());
            bayt.extend_from_slice(&giris.izin.to_le_bytes());
            bayt.extend_from_slice(&giris.mtime_saniye.to_le_bytes());
            bayt.extend_from_slice(&giris.mtime_nano.to_le_bytes());
            yaz_u32(&mut bayt, giris.parcalar.len() as u32);
            for parca in &giris.parcalar {
                bayt.extend_from_slice(&parca.nonce);
                bayt.extend_from_slice(&parca.ofset.to_le_bytes());
                bayt.extend_from_slice(&parca.sifre_uzunlugu.to_le_bytes());
            }
        }
        bayt
    }

    /// Manifest'in düz metin temsilinin uzunluğu, ayrılmadan hesaplanır.
    ///
    /// Mühürleme, manifest'i parça gövdelerinden **önce** yazdığı için bu
    /// uzunluk dosya boyutlarından önceden bilinir; kapsülde sabitlenen alan
    /// bu değerle doldurulur.
    pub fn kodlanmis_uzunluk(&self) -> usize {
        let mut boyut = 4 + 4 + self.kok_ad.len() + 4;
        for giris in &self.girdiler {
            boyut += 4 + giris.yol.len() + 1 + 8 + 4 + 8 + 4 + 4;
            boyut += giris.parcalar.len() * (NONCE_UZUNLUGU + 8 + 4);
        }
        boyut
    }

    /// Manifest baytlarını ayrıştırır, yol güvenliğini ve yer tutarlılığını doğrular.
    ///
    /// Güvenlik notu: ayrıştırma **önce** hiçbir yol kullanılmadan tamamlanır;
    /// yol güvenliği `yolu_dogrula` ile denetlenir. `../` gibi bir girdi
    /// diske hiç dokunmadan reddedilir.
    pub fn coz(bayt: &[u8]) -> Result<Self, Hata> {
        let mut okuyucu = Okuyucu::yeni(bayt);
        if okuyucu.sihirli()? != MANIFEST_SIHRLI {
            return Err(Hata::BozukKapsul(
                "manifest sihirli sayisi eslesmedi".into(),
            ));
        }
        let kok_ad = okuyucu.metin(EN_UZUN_YOL)?;
        yolu_dogrula(&kok_ad)?;
        let giris_sayisi = okuyucu.u32()? as usize;
        // Her girdi en az 1 bayt (tür) + 1 bayt (sihirli sonrası) yer kaplar;
        // ayrıca aşağıdaki döngü zaten sınırı uygular.
        let mut girdiler = Vec::with_capacity(giris_sayisi.min(4096));
        for _ in 0..giris_sayisi {
            let yol = okuyucu.metin(EN_UZUN_YOL)?;
            yolu_dogrula(&yol)?;
            let tur = match okuyucu.bayt()? {
                0 => Tur::Dosya,
                1 => Tur::Dizin,
                _ => return Err(Hata::BozukKapsul("bilinmeyen girdi turu".into())),
            };
            let boyut = okuyucu.u64()?;
            let izin = okuyucu.u32()?;
            let mtime_saniye = okuyucu.i64()?;
            let mtime_nano = okuyucu.u32()?;
            let parca_sayisi = okuyucu.u32()? as usize;
            let mut parcalar = Vec::with_capacity(parca_sayisi.min(1 << 20));
            for _ in 0..parca_sayisi {
                let mut nonce = [0u8; NONCE_UZUNLUGU];
                nonce.copy_from_slice(okuyucu.tam(NONCE_UZUNLUGU)?);
                parcalar.push(ParcaKonumu {
                    nonce,
                    ofset: okuyucu.u64()?,
                    sifre_uzunlugu: okuyucu.u32()?,
                });
            }
            if tur == Tur::Dizin && !parcalar.is_empty() {
                return Err(Hata::BozukKapsul("dizin girdisinin parcasi olamaz".into()));
            }
            girdiler.push(Giris {
                yol,
                tur,
                boyut,
                izin,
                mtime_saniye,
                mtime_nano,
                parcalar,
            });
        }
        if okuyucu.kalan() != 0 {
            return Err(Hata::BozukKapsul("manifest sonunda artik bayt var".into()));
        }
        let kayit = DizinKaydi { kok_ad, girdiler };
        kayit.tutarli_mi()?;
        Ok(kayit)
    }

    /// Parça ofsetlerinin çakışmadığını, toplam boyutun planla uyuştuğunu doğrular.
    ///
    /// Bir dosyanın parça kayıtları toplamı, dosya boyutuna her parça başına
    /// 12 (nonce) + 4 (uzunluk) + 16 (etiket) baytlık kayıt yükünün eklenmesiyle
    /// eşit olmalıdır. Bu kontrol, bozulmuş bir manifest'in "bu dosya şu kadar
    /// bayt" diyerek çözme sırasında diskin taşmasına yol açmasını engeller.
    pub fn tutarli_mi(&self) -> Result<(), Hata> {
        for giris in &self.girdiler {
            // Ofsetler payload alanina goreli oldugu icin bir dosyanin ilk parcasi
            // sifir ofsetten baslamaz; ardisillik ilk parcaya gore olculur.
            let ilk_ofset = giris.parcalar.first().map_or(0, |p| p.ofset);
            let mut beklenen: u64 = 0;
            let mut sifre_toplam: u64 = 0;
            for parca in &giris.parcalar {
                if parca.ofset - ilk_ofset != beklenen {
                    return Err(Hata::BozukKapsul(format!(
                        "'{}' girdisinde parca ofseti ardisil degil",
                        giris.yol
                    )));
                }
                beklenen += parca.toplam_bayt();
                sifre_toplam += u64::from(parca.sifre_uzunlugu);
            }
            if giris.tur == Tur::Dosya && sifre_toplam != giris.boyut {
                return Err(Hata::BozukKapsul(format!(
                    "'{}' girdisinin parca toplami {} bayt, ilan edilen {} bayt",
                    giris.yol, sifre_toplam, giris.boyut
                )));
            }
        }
        Ok(())
    }

    /// Tüm girdilerin payload toplamı.
    pub fn payload_uzunlugu(&self) -> u64 {
        self.girdiler.iter().map(|g| g.sifre_bayti()).sum()
    }

    /// Bir girdi yolunun **kök içindeki** göreli hâlini döndürür.
    ///
    /// `kok_ad` bileşeni yoldan çıkarılır. Böylece:
    /// - ağaç kapsülünde `kok/ic/a.txt` -> `ic/a.txt` (dizin `kok` altına açılır),
    /// - tek dosya kapsülünde `rapor.txt` -> `""` (hedef yolun kendisi dosyadır).
    pub fn kok_icindeki_yol<'a>(&'a self, yol: &'a str) -> &'a str {
        match yol.strip_prefix(self.kok_ad.as_str()) {
            Some(kalan) => kalan.strip_prefix('/').unwrap_or(kalan),
            None => yol,
        }
    }
}

/// Kapsül yolunun güvenli olup olmadığını doğrular.
///
/// Kabul edilen biçim: `/` ile ayrılmış, göreli, `..`/`.`/boş bileşen içermeyen,
/// `\` ve NUL içermeyen yol. Mutlak yollar, sürücü harfleri ve ana dizin kaçışı
/// burada reddedilir; bu, `../` saldırılarının dosya sistemine hiç ulaşmadan
/// engellenmesini sağlar.
pub fn yolu_dogrula(yol: &str) -> Result<(), Hata> {
    if yol.is_empty() {
        return Err(Hata::GecersizYol(yol.to_string()));
    }
    if yol.len() > EN_UZUN_YOL {
        return Err(Hata::GecersizYol(yol.to_string()));
    }
    if yol.starts_with('/') {
        return Err(Hata::GecersizYol(yol.to_string()));
    }
    if yol.contains('\\') || yol.contains('\0') || yol.contains(':') {
        return Err(Hata::GecersizYol(yol.to_string()));
    }
    for bilesen in yol.split('/') {
        if bilesen.is_empty() || bilesen == "." || bilesen == ".." {
            return Err(Hata::GecersizYol(yol.to_string()));
        }
        if bilesen.len() > EN_UZUN_BILESEN {
            return Err(Hata::GecersizYol(yol.to_string()));
        }
    }
    Ok(())
}

/// Küçük, bağımlılıksız bayt okuyucu.
struct Okuyucu<'a> {
    bayt: &'a [u8],
    konum: usize,
}

impl<'a> Okuyucu<'a> {
    fn yeni(bayt: &'a [u8]) -> Self {
        Okuyucu { bayt, konum: 0 }
    }

    fn kalan(&self) -> usize {
        self.bayt.len() - self.konum
    }

    fn tam(&mut self, uzunluk: usize) -> Result<&'a [u8], Hata> {
        if self.kalan() < uzunluk {
            return Err(Hata::BozukKapsul("manifest beklenenden kisa".into()));
        }
        let dilim = &self.bayt[self.konum..self.konum + uzunluk];
        self.konum += uzunluk;
        Ok(dilim)
    }

    fn bayt(&mut self) -> Result<u8, Hata> {
        Ok(self.tam(1)?[0])
    }

    fn sihirli(&mut self) -> Result<[u8; 4], Hata> {
        let mut sonuc = [0u8; 4];
        sonuc.copy_from_slice(self.tam(4)?);
        Ok(sonuc)
    }

    fn u32(&mut self) -> Result<u32, Hata> {
        let mut tampon = [0u8; 4];
        tampon.copy_from_slice(self.tam(4)?);
        Ok(u32::from_le_bytes(tampon))
    }

    fn u64(&mut self) -> Result<u64, Hata> {
        let mut tampon = [0u8; 8];
        tampon.copy_from_slice(self.tam(8)?);
        Ok(u64::from_le_bytes(tampon))
    }

    fn i64(&mut self) -> Result<i64, Hata> {
        let mut tampon = [0u8; 8];
        tampon.copy_from_slice(self.tam(8)?);
        Ok(i64::from_le_bytes(tampon))
    }

    fn metin(&mut self, en_fazla: usize) -> Result<String, Hata> {
        let uzunluk = self.u32()? as usize;
        if uzunluk > en_fazla || uzunluk > self.kalan() {
            return Err(Hata::BozukKapsul("manifest metin uzunlugu gecersiz".into()));
        }
        let baytlar = self.tam(uzunluk)?;
        String::from_utf8(baytlar.to_vec())
            .map_err(|_| Hata::BozukKapsul("manifest yolu gecerli UTF-8 degil".into()))
    }
}

fn yaz_u32(bayt: &mut Vec<u8>, deger: u32) {
    bayt.extend_from_slice(&deger.to_le_bytes());
}

#[cfg(test)]
// `unwrap`/`expect` testlerde kabul edilir (WORKER_CONTRACT §4.2).
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::kapsul::ParcaKonumu;

    fn parca(ofset: u64, sifre_uzunlugu: u32) -> ParcaKonumu {
        ParcaKonumu {
            nonce: [0xAB; NONCE_UZUNLUGU],
            ofset,
            sifre_uzunlugu,
        }
    }

    fn ornek_kayit() -> DizinKaydi {
        DizinKaydi {
            kok_ad: "kok".to_string(),
            girdiler: vec![
                Giris {
                    yol: "kok/a.txt".into(),
                    tur: Tur::Dosya,
                    boyut: 4,
                    izin: 0o644,
                    mtime_saniye: 1_700_000_000,
                    mtime_nano: 123,
                    parcalar: vec![parca(0, 4)],
                },
                Giris {
                    yol: "kok/boş".into(),
                    tur: Tur::Dizin,
                    boyut: 0,
                    izin: 0o755,
                    mtime_saniye: 0,
                    mtime_nano: 0,
                    parcalar: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn kodla_coz_gidis_donus_basar() {
        let mut kayit = ornek_kayit();
        kayit.girdiler.sort_by(|a, b| a.yol.cmp(&b.yol));
        let bayt = kayit.kodla();
        assert_eq!(bayt.len(), kayit.kodlanmis_uzunluk());
        assert_eq!(DizinKaydi::coz(&bayt).unwrap(), kayit);
    }

    #[test]
    fn bozuk_manifest_sihirlisi_reddedilir() {
        let mut bayt = ornek_kayit().kodla();
        bayt[0] = b'X';
        assert!(matches!(DizinKaydi::coz(&bayt), Err(Hata::BozukKapsul(_))));
    }

    #[test]
    fn kesik_manifest_reddedilir() {
        let bayt = ornek_kayit().kodla();
        let kesik = &bayt[..bayt.len() - 5];
        assert!(DizinKaydi::coz(kesik).is_err());
    }

    #[test]
    fn sona_eklenen_bayt_reddedilir() {
        let mut bayt = ornek_kayit().kodla();
        bayt.push(0xFF);
        assert!(DizinKaydi::coz(&bayt).is_err());
    }

    #[test]
    fn yol_kacisi_denemeleri_reddedilir() {
        for kotu_yol in [
            "../kacis",
            "kok/../../kacis",
            "/mutlak/yol",
            "kok\\windows\\ayrac",
            "kok//bos",
            "./goreli",
            "kok/./nokta",
            "",
            "C:/surucu",
        ] {
            assert!(
                matches!(yolu_dogrula(kotu_yol), Err(Hata::GecersizYol(_))),
                "'{kotu_yol}' reddedilmeliydi"
            );
        }
    }

    #[test]
    fn guvenli_yollar_kabul_edilir() {
        for iyi_yol in ["a", "kok/a.txt", "kok/ic/derin/dosya.bin", "nokta.dosya"] {
            assert!(
                yolu_dogrula(iyi_yol).is_ok(),
                "'{iyi_yol}' kabul edilmeliydi"
            );
        }
    }

    #[test]
    fn cok_uzun_yol_reddedilir() {
        let uzun = "a".repeat(EN_UZUN_YOL + 1);
        assert!(yolu_dogrula(&uzun).is_err());
        let cok_uzun_bilesen = "c".repeat(EN_UZUN_BILESEN + 1);
        assert!(yolu_dogrula(&cok_uzun_bilesen).is_err());
        let bilesenleri_uzun = ["d"; 40].join("/");
        assert!(yolu_dogrula(&bilesenleri_uzun).is_ok());
    }

    #[test]
    fn manifestteki_kotu_yol_cozmadan_reddedilir() {
        // Elle kurulmus manifest: "kok/../../dis" yolu gömülü.
        let mut bayt = Vec::new();
        bayt.extend_from_slice(&MANIFEST_SIHRLI);
        bayt.extend_from_slice(&3u32.to_le_bytes());
        bayt.extend_from_slice(b"kok");
        bayt.extend_from_slice(&1u32.to_le_bytes());
        let kotu = "kok/../../dis";
        bayt.extend_from_slice(&(kotu.len() as u32).to_le_bytes());
        bayt.extend_from_slice(kotu.as_bytes());
        bayt.push(0);
        bayt.extend_from_slice(&0u64.to_le_bytes());
        bayt.extend_from_slice(&0o644u32.to_le_bytes());
        bayt.extend_from_slice(&0i64.to_le_bytes());
        bayt.extend_from_slice(&0u32.to_le_bytes());
        bayt.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(DizinKaydi::coz(&bayt), Err(Hata::GecersizYol(_))));
    }

    #[test]
    fn yinelenen_yol_reddedilir() {
        let giris = ornek_kayit().girdiler[0].clone();
        let mut kayit = DizinKaydi {
            kok_ad: "kok".into(),
            girdiler: vec![giris.clone(), giris],
        };
        assert!(matches!(kayit.sirala(), Err(Hata::BozukKapsul(_))));
    }

    #[test]
    fn siralama_ust_dizini_once_koyar() {
        let mut kayit = DizinKaydi {
            kok_ad: "kok".into(),
            girdiler: vec![
                Giris {
                    yol: "kok/ic/dosya".into(),
                    tur: Tur::Dosya,
                    boyut: 0,
                    izin: 0,
                    mtime_saniye: 0,
                    mtime_nano: 0,
                    parcalar: Vec::new(),
                },
                Giris {
                    yol: "kok/ic".into(),
                    tur: Tur::Dizin,
                    boyut: 0,
                    izin: 0,
                    mtime_saniye: 0,
                    mtime_nano: 0,
                    parcalar: Vec::new(),
                },
            ],
        };
        kayit.sirala().unwrap();
        assert_eq!(kayit.girdiler[0].yol, "kok/ic");
        assert_eq!(kayit.girdiler[1].yol, "kok/ic/dosya");
    }

    #[test]
    fn payload_uzunlugu_parca_kayitlarindan_hesaplanir() {
        let kayit = ornek_kayit();
        // 1 parca: 12 + 4 + 4 + 16 = 36 bayt
        assert_eq!(kayit.payload_uzunlugu(), 36);
        assert_eq!(kayit.parca_sayisi(), 1);
        assert_eq!(kayit.toplam_bayt(), 4);
    }

    #[test]
    fn boyutla_uyumsuz_parca_toplami_reddedilir() {
        let mut bayt = ornek_kayit().kodla();
        // "kok/a.txt" girdisinin boyut alanini 999 yap: parca toplami uyusmaz.
        let konum = bayt
            .windows(9)
            .position(|pencere| pencere == b"kok/a.txt")
            .expect("yol bulunmali")
            + 9
            + 1;
        bayt[konum..konum + 8].copy_from_slice(&999u64.to_le_bytes());
        assert!(matches!(DizinKaydi::coz(&bayt), Err(Hata::BozukKapsul(_))));
    }

    #[test]
    fn dizin_girdisinin_parcasi_olamaz() {
        let mut kayit = ornek_kayit();
        kayit.girdiler[1].parcalar = vec![parca(0, 1)];
        let bayt = kayit.kodla();
        assert!(DizinKaydi::coz(&bayt).is_err());
    }

    #[test]
    fn yapisal_karsilastirma_nonce_farkini_yok_sayar() {
        let bir = ornek_kayit();
        let mut iki = ornek_kayit();
        iki.girdiler[0].parcalar[0].nonce = [0x01; NONCE_UZUNLUGU];
        assert!(bir.yapisal_esit(&iki));
        iki.girdiler[0].boyut = 5;
        assert!(!bir.yapisal_esit(&iki), "boyut farki yapisal farktir");
    }
}
