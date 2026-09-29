//! Akış hâlinde mühürleme ve çözme.
//!
//! Bu modülün **temel kabulü**: hiçbir aşamada bir dosyanın tamamı belleğe
//! alınmaz. Gövde sabit boyutlu parçalara bölünür, her parça ayrı bir tamponda
//! (varsayılan 2 MiB) şifrelenir ve hemen diske yazılır. Bellek tüketimi
//! dosya boyutundan bağımsızdır (rapor b08, kabul kriteri).
//!
//! Üç işlem sunar:
//!
//! - [`muhurle`] — dosya veya klasör ağacını kapsüle yazar.
//! - [`ac`] — kapsülü doğrular ve içeriği hedefe geri yükler.
//! - `dogrulama` modülü — kapsülü çözmeden yalnızca etiklerini sınar.
//!
//! ## Kaldığı yerden devam ve nonce güvenliği
//!
//! Devam özelliği, parça nonce'larının **asla yeniden kullanılmaması** kuralıyla
//! birlikte tasarlanmıştır. Devam sırasında şu güvenlik sözleşmesi uygulanır:
//!
//! 1. Yarım kalan geçici dosyanın manifest'i **kapsülün kendi anahtarıyla
//!    çözülür**; nonce'lar diskteki kayıttan alınır, yeniden üretilmez.
//! 2. `yazilan_offset` bir parça sınırı değilse devam **reddedilir** ve sıfırdan
//!    başlanır; böylece yarım yazılmış bir parça asla "tamam" sayılmaz.
//! 3. Dosya, `96 + manifest + yazilan_offset` uzunluğuna **kırpılır**. Kırpma
//!    sonrasında geriye kalan her parça ya tamamen yazılmıştır ya da hiç
//!    yazılmamıştır; ikinci durumdaki parçaların nonce'u henüz hiçbir şifre
//!    metniyle eşleşmemiştir, bu yüzden yeniden kullanılması güvenlidir.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroizing;

use crate::dizin::{DizinKaydi, Giris, Tur};
use crate::gezgin::tara;
use crate::hata::Hata;
use crate::kapsul::{
    parca_kayit_uzunlugu, ParcaKonumu, SabitBaslik, BASLIK_UZUNLUGU, BAYRAK_DIZIN, DURUM_TAMAM,
    DURUM_YAZILIYOR, ETIKET_UZUNLUGU, NONCE_UZUNLUGU, OZET_UZUNLUGU, SIHRLI, TUZ_UZUNLUGU,
    VARSAYILAN_PARCA,
};
use crate::kripto::{
    alt_anahtar, ana_malzeme_turet, kapsul_ozeti, manifest_coz, manifest_sifrele, nonce_uret,
    ozitler_esit, parca_coz, parca_ek_verisi, parca_sifrele, Argon2Ayar, AMAÇ_ANA, AMAÇ_DOSYA,
    ANAHTAR_UZUNLUGU,
};

/// Yarım kalmış mühürlemenin geçici dosya eki.
const GECICI_EKI: &str = "sbxtmp";

/// İlerleme geri çağrısının alabileceği olay.
#[derive(Clone, Debug)]
pub struct Ilerleme {
    /// İşin hangi aşamada olduğu (`"taraniyor"`, `"sifreleniyor"`, `"ozetleniyor"`, `"cozuluyor"`).
    pub asama: &'static str,
    /// Tamamlanan parça sayısı.
    pub parca: u64,
    /// Toplam parça sayısı (bilinmiyorsa `0`).
    pub toplam_parca: u64,
    /// Tamamlanan dosya sayısı.
    pub dosya: u64,
    /// Toplam dosya sayısı.
    pub toplam_dosya: u64,
}

/// İlerleme/iptal geri çağrısının tipi.
///
/// Geri çağrı `Err` döndürerek işi durdurur (rapor b03/S3, b16: kesinti
/// kurtarma). `Send + Sync` kısıtı, geri çağrının gelecekte bir iş parçacığına
/// taşınabilmesi için gereklidir.
pub type IlerlemeGeriCagri = Arc<dyn Fn(Ilerleme) -> Result<(), Hata> + Send + Sync>;

/// Mühürleme seçenekleri.
#[derive(Clone)]
pub struct MuhurSecenekleri {
    /// Parça boyutu (bayt); 512 KiB .. 8 MiB.
    pub parca_boyutu: u32,
    /// Argon2id parametreleri.
    pub argon2: Argon2Ayar,
    /// Hedef dosya varsa üzerine yazılsın mı.
    pub ustune_yaz: bool,
    /// Yarım kalmış geçici dosyadan kaldığı yerden devam edilsin mi.
    pub devam: bool,
    /// İlerleme ve iptal geri çağrısı.
    pub ilerleme: Option<IlerlemeGeriCagri>,
}

impl Default for MuhurSecenekleri {
    fn default() -> Self {
        MuhurSecenekleri {
            parca_boyutu: VARSAYILAN_PARCA,
            argon2: Argon2Ayar::default(),
            ustune_yaz: false,
            devam: false,
            ilerleme: None,
        }
    }
}

impl std::fmt::Debug for MuhurSecenekleri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuhurSecenekleri")
            .field("parca_boyutu", &self.parca_boyutu)
            .field("argon2", &self.argon2)
            .field("ustune_yaz", &self.ustune_yaz)
            .field("devam", &self.devam)
            .field("ilerleme", &self.ilerleme.is_some())
            .finish()
    }
}

impl MuhurSecenekleri {
    fn bildir(
        &self,
        asama: &'static str,
        parca: u64,
        toplam_parca: u64,
        dosya: u64,
        toplam_dosya: u64,
    ) -> Result<(), Hata> {
        match &self.ilerleme {
            Some(geri) => geri(Ilerleme {
                asama,
                parca,
                toplam_parca,
                dosya,
                toplam_dosya,
            }),
            None => Ok(()),
        }
    }
}

/// Geri yükleme seçenekleri.
#[derive(Clone)]
pub struct AcSecenekleri {
    /// Hedef dosya/dizin varsa üzerine yazılsın mı.
    pub ustune_yaz: bool,
    /// Kapsülün SHA-512 kuyruk özeti doğrulansın mı.
    pub kuyruk_ozetini_dogrula: bool,
    /// İlerleme ve iptal geri çağrısı.
    pub ilerleme: Option<IlerlemeGeriCagri>,
}

impl Default for AcSecenekleri {
    fn default() -> Self {
        AcSecenekleri {
            ustune_yaz: false,
            kuyruk_ozetini_dogrula: true,
            ilerleme: None,
        }
    }
}

impl std::fmt::Debug for AcSecenekleri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcSecenekleri")
            .field("ustune_yaz", &self.ustune_yaz)
            .field("kuyruk_ozetini_dogrula", &self.kuyruk_ozetini_dogrula)
            .field("ilerleme", &self.ilerleme.is_some())
            .finish()
    }
}

impl AcSecenekleri {
    fn bildir(
        &self,
        asama: &'static str,
        parca: u64,
        toplam: u64,
        dosya: u64,
        toplam_dosya: u64,
    ) -> Result<(), Hata> {
        match &self.ilerleme {
            Some(geri) => geri(Ilerleme {
                asama,
                parca,
                toplam_parca: toplam,
                dosya,
                toplam_dosya,
            }),
            None => Ok(()),
        }
    }
}

/// Mühürleme sonucunda döndürülen özet.
#[derive(Clone, Debug)]
pub struct MuhurRaporu {
    /// Yazılan kapsülün yolu.
    pub kapsul: PathBuf,
    /// Taranan kaynağın yolu.
    pub kaynak: PathBuf,
    /// Kapsüldeki dosya sayısı (dizinler hariç).
    pub dosya_sayisi: u64,
    /// Kapsüldeki dizin sayısı (kök dizin hariç).
    pub dizin_sayisi: u64,
    /// Toplam parça sayısı.
    pub parca_sayisi: u64,
    /// Şifrelenen düz metin baytı.
    pub girdi_bayti: u64,
    /// Kapsül dosyasının toplam uzunluğu (bayt).
    pub kapsul_bayti: u64,
    /// Kaldığı yerden devam edildiyse `true`.
    pub devam_edildi: bool,
    /// Geçen süre (milisaniye).
    pub sure_ms: u128,
}

/// Geri yükleme sonucunda döndürülen özet.
#[derive(Clone, Debug)]
pub struct AcRaporu {
    /// Yazılan hedefin yolu.
    pub hedef: PathBuf,
    /// Oluşturulan dosya sayısı.
    pub dosya_sayisi: u64,
    /// Oluşturulan dizin sayısı (kök dizin dâhil).
    pub dizin_sayisi: u64,
    /// Etiketi doğrulanıp çözülen parça sayısı.
    pub parca_sayisi: u64,
    /// Geri yüklenen düz metin baytı.
    pub cikti_bayti: u64,
    /// Kapsülün SHA-512 kuyruk özeti doğrulandı mı.
    pub kuyruk_ozeti_dogrulandi: bool,
    /// Saklanan izinlerin uygulanamadığı dosya sayısı (NTFS ACL dâhil).
    pub izin_uygulanamadi: u64,
    /// Geçen süre (milisaniye).
    pub sure_ms: u128,
}

/// Kapsül başlığı ve manifest'ten okunan özet bilgiler.
#[derive(Clone, Debug)]
pub struct KapsulOzeti {
    /// Biçim sürümü.
    pub surum: u8,
    /// Parça boyutu (bayt).
    pub parca_boyutu: u32,
    /// Argon2 parametreleri (başlıkta açıkça saklanır).
    pub argon2: Argon2Ayar,
    /// Kapsül bir klasör ağacı mı.
    pub dizin_agaci: bool,
    /// Kapsül kök dizinin adı.
    pub kok_ad: String,
    /// Girdi sayısı (dosya + dizin).
    pub girdi_sayisi: u64,
    /// Parça sayısı.
    pub parca_sayisi: u64,
    /// Şifrlenen düz metin baytı.
    pub girdi_bayti: u64,
    /// Kapsül dosyasının uzunluğu (bayt).
    pub kapsul_bayti: u64,
    /// Parça başına ek yükün (nonce + uzunluk + etiket) düz metne oranı (yüzde).
    pub etik_yuku_yuzdesi: f64,
    /// Kapsül düzeyi SHA-512 kuyruk özeti doğrulandı mı.
    pub kuyruk_ozeti_dogrulandi: bool,
}

// ---------------------------------------------------------------------------
// Planlama
// ---------------------------------------------------------------------------

struct Plan {
    /// Manifest'teki göreli yolların çözüleceği kök dizin.
    ///
    /// Ağaç kapsülünde bu, taranan klasörün kendisidir (yollar `ust.txt`,
    /// `ic/orta.txt` biçimindedir). Tek dosya kapsülünde ise dosyanın bulunduğu
    /// dizindir (tek giriş yolu dosyanın adıdır).
    kok: PathBuf,
    dizin_agaci: bool,
    parca_boyutu: u32,
    manifest: DizinKaydi,
    manifest_ayrilmis: u64,
    payload_len: u64,
    parca_sayisi: u64,
    dosya_sayisi: u64,
    dizin_sayisi: u64,
    toplam_bayt: u64,
}

impl Plan {
    fn olustur(kaynak: &Path, parca_boyutu: u32) -> Result<Self, Hata> {
        if parca_boyutu == 0 {
            return Err(Hata::BozukArguman("parca boyutu sifir olamaz".into()));
        }
        let taranmis = tara(kaynak)?;
        let mut payload_len: u64 = 0;
        let mut parca_sayisi: u64 = 0;
        let mut girdiler: Vec<Giris> = Vec::with_capacity(taranmis.kayitlar.len());

        for kayit in &taranmis.kayitlar {
            let mut parcalar: Vec<ParcaKonumu> = Vec::new();
            if kayit.tur == Tur::Dosya {
                let kalan_mut = |kalan: u64| -> u32 {
                    if kalan > u64::from(parca_boyutu) {
                        parca_boyutu
                    } else {
                        kalan as u32
                    }
                };
                let mut yazilan: u64 = 0;
                while yazilan < kayit.boyut {
                    let sifre_uzunlugu = kalan_mut(kayit.boyut - yazilan);
                    parcalar.push(ParcaKonumu {
                        nonce: nonce_uret()?,
                        ofset: payload_len,
                        sifre_uzunlugu,
                    });
                    payload_len += parca_kayit_uzunlugu(sifre_uzunlugu);
                    yazilan += u64::from(sifre_uzunlugu);
                    parca_sayisi += 1;
                }
            }
            girdiler.push(Giris {
                yol: kayit.goreli_yol.clone(),
                tur: kayit.tur,
                boyut: kayit.boyut,
                izin: kayit.izin,
                mtime_saniye: kayit.mtime_saniye,
                mtime_nano: kayit.mtime_nano,
                parcalar,
            });
        }

        let mut manifest = DizinKaydi {
            kok_ad: taranmis.kok_ad,
            girdiler,
        };
        manifest.sirala()?;
        let dosya_sayisi = manifest
            .girdiler
            .iter()
            .filter(|g| g.tur == Tur::Dosya)
            .count() as u64;
        let dizin_sayisi = manifest
            .girdiler
            .iter()
            .filter(|g| g.tur == Tur::Dizin)
            .count() as u64;
        let toplam_bayt = manifest.toplam_bayt();
        let manifest_ayrilmis = manifest.kodlanmis_uzunluk() as u64 + ETIKET_UZUNLUGU as u64;
        let kok = if taranmis.dizin_agaci {
            kaynak.to_path_buf()
        } else {
            kaynak
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        };
        Ok(Plan {
            kok,
            dizin_agaci: taranmis.dizin_agaci,
            parca_boyutu,
            manifest,
            manifest_ayrilmis,
            payload_len,
            parca_sayisi,
            dosya_sayisi,
            dizin_sayisi,
            toplam_bayt,
        })
    }
}

fn gecici_yol_uret(kapsul_yolu: &Path) -> PathBuf {
    let mut ad = kapsul_yolu.as_os_str().to_os_string();
    ad.push(".");
    ad.push(GECICI_EKI);
    PathBuf::from(ad)
}

fn parca_sinirinda_mi(manifest: &DizinKaydi, ofset: u64) -> bool {
    let mut toplam: u64 = 0;
    if ofset == 0 {
        return true;
    }
    for giris in &manifest.girdiler {
        for parca in &giris.parcalar {
            toplam += parca.toplam_bayt();
            if toplam == ofset {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Mühürleme
// ---------------------------------------------------------------------------

/// Bir dosya veya klasör ağacını kapsül olarak mühürler.
///
/// Akış disiplini: kaynak taranır, boyutlardan parça planı ve manifest uzunluğu
/// **önceden hesaplanır**, başlık ve şifreli manifest yazılır, ardından gövde
/// sabit tamponla akıtılır. Mühürleme yarıda kesilirse geçici dosya silinir
/// (kullanıcı `devam` isterse korunur ve kaldığı yerden sürdürülür).
pub fn muhurle(
    kaynak: &Path,
    kapsul_yolu: &Path,
    parola: &[u8],
    secenek: &MuhurSecenekleri,
) -> Result<MuhurRaporu, Hata> {
    let baslangic = Instant::now();
    if parola.is_empty() {
        return Err(Hata::BozukArguman("parola bos olamaz".into()));
    }
    secenek.argon2.dogrula()?;
    if !(crate::kapsul::EN_KUCUK_PARCA..=crate::kapsul::EN_BUYUK_PARCA)
        .contains(&secenek.parca_boyutu)
    {
        return Err(Hata::BozukArguman(format!(
            "parca boyutu {} bayt; izinli aralik {}..{}",
            secenek.parca_boyutu,
            crate::kapsul::EN_KUCUK_PARCA,
            crate::kapsul::EN_BUYUK_PARCA
        )));
    }
    if kapsul_yolu.exists() && !secenek.ustune_yaz {
        return Err(Hata::VarOluyor(kapsul_yolu.display().to_string()));
    }

    let plan = Plan::olustur(kaynak, secenek.parca_boyutu)?;
    secenek.bildir("taraniyor", 0, plan.parca_sayisi, 0, plan.dosya_sayisi)?;

    let gecici_yol = gecici_yol_uret(kapsul_yolu);
    let sonuc = muhurle_gecici(&plan, &gecici_yol, parola, secenek);
    let devam_edildi = match sonuc {
        Ok(devam) => devam,
        Err(hata) => {
            if !secenek.devam {
                // Rapor b03/S3: kismi cikti kullanilmaz, gecici dosya silinir.
                let _ = std::fs::remove_file(&gecici_yol);
            }
            return Err(hata);
        }
    };

    if kapsul_yolu.exists() {
        if !secenek.ustune_yaz {
            let _ = std::fs::remove_file(&gecici_yol);
            return Err(Hata::VarOluyor(kapsul_yolu.display().to_string()));
        }
        std::fs::remove_file(kapsul_yolu)?;
    }
    std::fs::rename(&gecici_yol, kapsul_yolu)?;

    Ok(MuhurRaporu {
        kapsul: kapsul_yolu.to_path_buf(),
        kaynak: kaynak.to_path_buf(),
        dosya_sayisi: plan.dosya_sayisi,
        dizin_sayisi: plan.dizin_sayisi,
        parca_sayisi: plan.parca_sayisi,
        girdi_bayti: plan.toplam_bayt,
        kapsul_bayti: BASLIK_UZUNLUGU as u64
            + plan.manifest_ayrilmis
            + plan.payload_len
            + OZET_UZUNLUGU as u64,
        devam_edildi,
        sure_ms: baslangic.elapsed().as_millis(),
    })
}

/// Geçici dosyayı açar, gövdeyi yazar; kaldığı yerden devam edildiyse `true` döndürür.
fn muhurle_gecici(
    plan: &Plan,
    gecici_yol: &Path,
    parola: &[u8],
    secenek: &MuhurSecenekleri,
) -> Result<bool, Hata> {
    if gecici_yol.exists() {
        if secenek.devam {
            if let Some((dosya, baslik, ana_anahtar, tuz, kayitli)) =
                devam_ac(gecici_yol, plan, parola)?
            {
                let devam = baslik.yazilan_offset > 0;
                muhurle_govde(dosya, plan, secenek, &baslik, &ana_anahtar, &tuz, &kayitli)?;
                return Ok(devam);
            }
        }
        std::fs::remove_file(gecici_yol)?;
    }
    let mut dosya = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(gecici_yol)
        .map_err(|hata| {
            if hata.kind() == std::io::ErrorKind::AlreadyExists {
                Hata::VarOluyor(gecici_yol.display().to_string())
            } else {
                Hata::Io(hata)
            }
        })?;
    let tuz = crate::kripto::rastgele_bayt(TUZ_UZUNLUGU)?;
    let tuz_dizi: [u8; TUZ_UZUNLUGU] = tuz[..TUZ_UZUNLUGU]
        .try_into()
        .map_err(|_| Hata::Kriptografik("tuz uzunlugu hatasi".into()))?;
    let malzeme = ana_malzeme_turet(parola, &tuz_dizi, &secenek.argon2)?;
    let ana_anahtar = alt_anahtar(&malzeme, &tuz_dizi, AMAÇ_ANA, 0)?;
    let baslik = SabitBaslik {
        bayraklar: if plan.dizin_agaci { BAYRAK_DIZIN } else { 0 },
        parca_boyutu: plan.parca_boyutu,
        argon2_bellek_kib: secenek.argon2.bellek_kib,
        argon2_tur: secenek.argon2.tur,
        argon2_yol: secenek.argon2.yol,
        manifest_nonce: nonce_uret()?,
        girdi_sayisi: plan.manifest.girdiler.len() as u32,
        manifest_ayrilmis: plan.manifest_ayrilmis,
        payload_planlanan: plan.payload_len,
        yazilan_offset: 0,
        durum: DURUM_YAZILIYOR,
    };
    let mut kodlu = baslik.kodla();
    SabitBaslik::tuz_yaz(&mut kodlu, &tuz_dizi);
    dosya.write_all(&kodlu)?;
    muhurle_govde(
        dosya,
        plan,
        secenek,
        &baslik,
        &ana_anahtar,
        &tuz_dizi,
        &plan.manifest,
    )?;
    Ok(false)
}

/// Yarım kalmış geçici dosyayı devam için açar; uygun değilse `None` döner.
///
/// Dönüş değerindeki `DizinKaydi` **diskteki** manifest'tir: parça nonce'ları
/// buradan gelir. Böylece daha önce yazılmış parçaların nonce'u ile bundan
/// sonra yazılacak parçaların nonce'u çakışmaz.
#[allow(clippy::type_complexity)]
fn devam_ac(
    gecici_yol: &Path,
    plan: &Plan,
    parola: &[u8],
) -> Result<
    Option<(
        File,
        SabitBaslik,
        Zeroizing<[u8; ANAHTAR_UZUNLUGU]>,
        [u8; TUZ_UZUNLUGU],
        DizinKaydi,
    )>,
    Hata,
> {
    let mut dosya = match OpenOptions::new().read(true).write(true).open(gecici_yol) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };
    let mut kodlu = [0u8; BASLIK_UZUNLUGU];
    if dosya.read_exact(&mut kodlu).is_err() || kodlu[0..4] != SIHRLI {
        return Ok(None);
    }
    let baslik = match SabitBaslik::coz(&kodlu) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };
    // Kaynak degismisse (farkli yol/boyut/parca) devam reddedilir.
    if baslik.durum != DURUM_YAZILIYOR
        || baslik.parca_boyutu != plan.parca_boyutu
        || baslik.manifest_ayrilmis != plan.manifest_ayrilmis
        || baslik.payload_planlanan != plan.payload_len
        || baslik.girdi_sayisi != plan.manifest.girdiler.len() as u32
    {
        return Ok(None);
    }
    let tuz = SabitBaslik::tuz(&kodlu);
    let ayar = Argon2Ayar {
        bellek_kib: baslik.argon2_bellek_kib,
        tur: baslik.argon2_tur,
        yol: baslik.argon2_yol,
    };
    ayar.dogrula()?;
    let malzeme = ana_malzeme_turet(parola, &tuz, &ayar)?;
    let ana_anahtar = alt_anahtar(&malzeme, &tuz, AMAÇ_ANA, 0)?;
    // Diskteki manifest okunur; parca nonce'lari yeniden uretilmez.
    let kayitli = match manifest_oku(&mut dosya, &baslik, &ana_anahtar, &kodlu) {
        Ok(kayit) => kayit,
        Err(_) => return Ok(None),
    };
    if !kayitli.yapisal_esit(&plan.manifest) {
        return Ok(None);
    }
    if !parca_sinirinda_mi(&kayitli, baslik.yazilan_offset) {
        return Ok(None);
    }
    // Yarim yazilmis son parcayi at: yalnizca tam parca sinirlari korunur.
    let hedef = BASLIK_UZUNLUGU as u64 + baslik.manifest_ayrilmis + baslik.yazilan_offset;
    dosya.set_len(hedef)?;
    Ok(Some((dosya, baslik, ana_anahtar, tuz, kayitli)))
}

/// Geçici dosyadan şifreli manifest'i çözer.
fn manifest_oku(
    dosya: &mut File,
    baslik: &SabitBaslik,
    ana_anahtar: &[u8; ANAHTAR_UZUNLUGU],
    kodlu_baslik: &[u8; BASLIK_UZUNLUGU],
) -> Result<DizinKaydi, Hata> {
    dosya.seek(SeekFrom::Start(BASLIK_UZUNLUGU as u64))?;
    let mut duz = Zeroizing::new(vec![0u8; baslik.manifest_ayrilmis as usize]);
    dosya.read_exact(duz.as_mut_slice())?;
    if duz.len() < ETIKET_UZUNLUGU {
        return Err(Hata::BozukKapsul("manifest etiketi eksik".into()));
    }
    let etiket_ofseti = duz.len() - ETIKET_UZUNLUGU;
    let etik: [u8; ETIKET_UZUNLUGU] = duz[etiket_ofseti..]
        .try_into()
        .map_err(|_| Hata::BozukKapsul("manifest etiketi okunamadi".into()))?;
    manifest_coz(
        ana_anahtar,
        &baslik.manifest_nonce,
        SabitBaslik::aad(kodlu_baslik),
        &mut duz[..etiket_ofseti],
        &etik,
    )?;
    DizinKaydi::coz(&duz[..etiket_ofseti])
}

fn muhurle_govde(
    mut dosya: File,
    plan: &Plan,
    secenek: &MuhurSecenekleri,
    baslik: &SabitBaslik,
    ana_anahtar: &[u8; ANAHTAR_UZUNLUGU],
    tuz: &[u8; TUZ_UZUNLUGU],
    etkin_manifest: &DizinKaydi,
) -> Result<(), Hata> {
    let mut kodlu_baslik = baslik.kodla();
    SabitBaslik::tuz_yaz(&mut kodlu_baslik, tuz);
    let mut duz_manifest = Zeroizing::new(etkin_manifest.kodla());
    let etiket = manifest_sifrele(
        ana_anahtar,
        &baslik.manifest_nonce,
        SabitBaslik::aad(&kodlu_baslik),
        duz_manifest.as_mut_slice(),
    )?;

    let payload_baslangic = BASLIK_UZUNLUGU as u64 + baslik.manifest_ayrilmis;
    dosya.seek(SeekFrom::Start(0))?;
    dosya.write_all(&kodlu_baslik)?;
    dosya.seek(SeekFrom::Start(BASLIK_UZUNLUGU as u64))?;
    dosya.write_all(&duz_manifest)?;
    dosya.write_all(&etiket)?;
    dosya.seek(SeekFrom::Start(payload_baslangic + baslik.yazilan_offset))?;
    dosya.set_len(payload_baslangic + baslik.yazilan_offset)?;

    // Sabit boyutlu tampon: bellege hicbir zaman parca boyutundan fazlasi girmez.
    let mut tampon = Zeroizing::new(vec![0u8; plan.parca_boyutu as usize]);
    let mut atlanan = 0u64;
    let mut yazilan_parca = 0u64;
    let mut tamamlanan_dosya = 0u64;

    for (sira, giris) in etkin_manifest.girdiler.iter().enumerate() {
        if giris.tur == Tur::Dizin {
            continue;
        }
        let alt = alt_anahtar(ana_anahtar, tuz, AMAÇ_DOSYA, sira as u64)?;
        let dosya_yolu = plan.kok.join(&giris.yol);
        let mut girdi = File::open(&dosya_yolu)?;
        if girdi.metadata()?.len() != giris.boyut {
            return Err(Hata::BozukArguman(format!(
                "'{}' muhurleme sirasinda boyut degistirdi",
                giris.yol
            )));
        }
        for (parca_sirasi, parca) in giris.parcalar.iter().enumerate() {
            // Duz metin **her zaman** sirayla okunur; devam edilen bir parcada
            // okuma atlanirsa dosya imleci geride kalir ve sonraki parcaya yanlis
            // veri girer.
            let okunan = tam_doldur(&mut girdi, tampon.as_mut_slice())?;
            if okunan as u32 != parca.sifre_uzunlugu {
                return Err(Hata::BozukArguman(format!(
                    "'{}' parcasi beklenenden kisa okundu",
                    giris.yol
                )));
            }
            if parca.ofset < baslik.yazilan_offset {
                // Bu parca onceki calismada tamamlanmis; yeniden uretilmez.
                atlanan += 1;
                continue;
            }
            let etik = parca_sifrele(
                &alt,
                &parca.nonce,
                &parca_ek_verisi(sira as u64, parca_sirasi as u64),
                &mut tampon[..okunan],
            )?;
            dosya.write_all(&parca.nonce)?;
            dosya.write_all(&parca.sifre_uzunlugu.to_le_bytes())?;
            dosya.write_all(&tampon[..okunan])?;
            dosya.write_all(&etik)?;
            let yeni_offset = parca.ofset + parca_kayit_uzunlugu(parca.sifre_uzunlugu);
            ilerleme_yaz(&mut dosya, payload_baslangic, yeni_offset)?;
            yazilan_parca += 1;
            secenek.bildir(
                "sifreleniyor",
                atlanan + yazilan_parca,
                plan.parca_sayisi,
                tamamlanan_dosya,
                plan.dosya_sayisi,
            )?;
        }
        tamamlanan_dosya += 1;
    }

    let toplam = payload_baslangic + plan.payload_len;
    let son_baslik = SabitBaslik {
        bayraklar: baslik.bayraklar,
        parca_boyutu: baslik.parca_boyutu,
        argon2_bellek_kib: baslik.argon2_bellek_kib,
        argon2_tur: baslik.argon2_tur,
        argon2_yol: baslik.argon2_yol,
        manifest_nonce: baslik.manifest_nonce,
        girdi_sayisi: baslik.girdi_sayisi,
        manifest_ayrilmis: baslik.manifest_ayrilmis,
        payload_planlanan: baslik.payload_planlanan,
        yazilan_offset: plan.payload_len,
        durum: DURUM_TAMAM,
    };
    let mut kodlu_son = son_baslik.kodla();
    SabitBaslik::tuz_yaz(&mut kodlu_son, tuz);
    dosya.seek(SeekFrom::Start(0))?;
    dosya.write_all(&kodlu_son)?;

    secenek.bildir(
        "ozetleniyor",
        plan.parca_sayisi,
        plan.parca_sayisi,
        plan.dosya_sayisi,
        plan.dosya_sayisi,
    )?;
    dosya.seek(SeekFrom::Start(0))?;
    let ozet = kapsul_ozeti(&mut dosya, toplam)?;
    dosya.seek(SeekFrom::Start(toplam))?;
    dosya.write_all(&ozet)?;
    dosya.flush()?;
    Ok(())
}

/// `yazilan_offset` alanını günceller; devamın güvenli sınırı budur.
///
/// Alan başlığın `[80..88]` aralığındadır ve AAD kapsamının **dışındadır**;
/// bu yüzden yarım kalan bir yazma AAD'yi bozmaz, en kötü halde devam daha
/// erken bir sınırdan başlar ve bazı parçalar yeniden yazılır.
fn ilerleme_yaz(dosya: &mut File, payload_baslangic: u64, yeni_offset: u64) -> Result<(), Hata> {
    dosya.seek(SeekFrom::Start(80))?;
    dosya.write_all(&yeni_offset.to_le_bytes())?;
    dosya.seek(SeekFrom::Start(payload_baslangic + yeni_offset))?;
    Ok(())
}

/// Tamponu kaynağın sonuna kadar doldurur; kısmi okuma ve `EINTR` durumlarını
/// yönetir. Genel bir `Read` imzası kullanır ki akış disiplini dosya türünden
/// bağımsız olarak test edilebilsin.
fn tam_doldur(girdi: &mut dyn Read, tampon: &mut [u8]) -> Result<usize, Hata> {
    let mut toplam = 0usize;
    while toplam < tampon.len() {
        match girdi.read(&mut tampon[toplam..]) {
            Ok(0) => break,
            Ok(okunan) => toplam += okunan,
            Err(hata) if hata.kind() == std::io::ErrorKind::Interrupted => {}
            Err(hata) => return Err(Hata::Io(hata)),
        }
    }
    Ok(toplam)
}

// ---------------------------------------------------------------------------
// Çözme
// ---------------------------------------------------------------------------

/// Bir kapsülü okur, doğrular ve hedefe geri yükler.
///
/// Parola doğruluğu manifest etiketiyle kanıtlanır; yanlış parola ile bozuk
/// manifest kriptografik olarak ayırt edilemez ve aynı hata mesajı döner. Her
/// parça, diske yazılmadan **önce** kendi etiketiyle doğrulanır.
pub fn ac(
    kapsul_yolu: &Path,
    hedef: &Path,
    parola: &[u8],
    secenek: &AcSecenekleri,
) -> Result<AcRaporu, Hata> {
    let baslangic = Instant::now();
    let (baslik, ana_anahtar, tuz) = kapsul_ac(kapsul_yolu, parola, secenek)?;
    if baslik.durum != DURUM_TAMAM {
        return Err(Hata::BozukKapsul(
            "kapsul yazilmamis; kaldigi yerden devam edin".into(),
        ));
    }
    let manifest = manifest_oku_dosyadan(kapsul_yolu, &baslik, &ana_anahtar)?;
    if baslik.payload_planlanan != manifest.payload_uzunlugu() {
        return Err(Hata::BozukKapsul(
            "basliktaki payload uzunlugu manifest ile uyusmuyor".into(),
        ));
    }
    // Uzerine yazma reddi: *geri yuklenen agacin* koku zaten varsa hicbir
    // dosyaya dokunulmaz. `hedef` yalnizca bir kapsayici oldugu icin var
    // olabilir; asil korunan nesne `hedef/<kok_ad>` agacidir.
    //
    // Tek dosya kapsulunde agac yoktur: kapsulun kok adi dosyanin kendi adidir,
    // bu yuzden `hedef` yolunun **kendisi** geri yuklenen dosyadir.
    let dizin_agaci = baslik.dizin_agaci();
    let kok = if dizin_agaci {
        hedef.join(&manifest.kok_ad)
    } else {
        hedef.to_path_buf()
    };
    if kok.exists() && !secenek.ustune_yaz {
        return Err(Hata::VarOluyor(kok.display().to_string()));
    }
    if kok.exists() {
        // Ustune yazma acikca istendiginde eski agac once kaldirilir; aksi halde
        // `create_new` her dosyada "AlreadyExists" ile kacar ve yari bir agac
        // geride kalirdi.
        if kok.is_dir() {
            std::fs::remove_dir_all(&kok)?;
        } else {
            std::fs::remove_file(&kok)?;
        }
    }
    if dizin_agaci {
        std::fs::create_dir_all(&kok)?;
    }

    let mut dosya = File::open(kapsul_yolu)?;
    let payload_baslangic = baslik.payload_ofseti();
    let toplam_parca = manifest.parca_sayisi();
    let toplam_dosya = manifest
        .girdiler
        .iter()
        .filter(|g| g.tur == Tur::Dosya)
        .count() as u64;
    let mut parca_sayisi = 0u64;
    let mut cikti_bayti = 0u64;
    let mut izin_uygulanamadi = 0u64;
    let mut olusan_dizinler: Vec<(&Giris, std::path::PathBuf)> = Vec::new();

    // Once tum dizinler olusturulur: girdiler yola gore sirali oldugu icin
    // ust dizin her zaman alt girdiden once gelir.
    for giris in &manifest.girdiler {
        if giris.tur != Tur::Dizin {
            continue;
        }
        let yol = kok.join(manifest.kok_icindeki_yol(&giris.yol));
        if !yol.is_dir() {
            std::fs::create_dir_all(&yol)?;
        }
        olusan_dizinler.push((giris, yol));
    }

    for (sira, giris) in manifest.girdiler.iter().enumerate() {
        if giris.tur != Tur::Dosya {
            continue;
        }
        // Tek dosya kapsulunde kok ici yol bos gelir: hedef yolun kendisi dosyadir.
        // `join("")` Windows'ta gecersiz bir ad uretir, bu yuzden ayrica ele alinir.
        let goreli = manifest.kok_icindeki_yol(&giris.yol);
        let yol = if goreli.is_empty() {
            kok.clone()
        } else {
            kok.join(goreli)
        };
        if let Some(ebeveyn) = yol.parent() {
            std::fs::create_dir_all(ebeveyn)?;
        }
        let alt = alt_anahtar(&ana_anahtar, &tuz, AMAÇ_DOSYA, sira as u64)?;
        let mut cikti = OpenOptions::new().write(true).create_new(true).open(&yol)?;
        let mut yazilan = 0u64;
        for (parca_sirasi, parca) in giris.parcalar.iter().enumerate() {
            let mut kayit = Zeroizing::new(vec![0u8; parca.toplam_bayt() as usize]);
            dosya.seek(SeekFrom::Start(payload_baslangic + parca.ofset))?;
            dosya.read_exact(kayit.as_mut_slice())?;
            let etiket_ofseti = NONCE_UZUNLUGU + 4 + parca.sifre_uzunlugu as usize;
            let etik: [u8; ETIKET_UZUNLUGU] = kayit[etiket_ofseti..etiket_ofseti + ETIKET_UZUNLUGU]
                .try_into()
                .map_err(|_| Hata::BozukKapsul("parca etiketi okunamadi".into()))?;
            let sifre = &mut kayit[NONCE_UZUNLUGU + 4..etiket_ofseti];
            parca_coz(
                &alt,
                &parca.nonce,
                &parca_ek_verisi(sira as u64, parca_sirasi as u64),
                sifre,
                &etik,
            )
            .map_err(|_| Hata::BozukParca {
                parca: parca_sirasi as u64,
                dosya: giris.yol.clone(),
            })?;
            cikti.write_all(sifre)?;
            yazilan += sifre.len() as u64;
            parca_sayisi += 1;
            secenek.bildir(
                "cozuluyor",
                parca_sayisi,
                toplam_parca,
                cikti_bayti,
                toplam_dosya,
            )?;
        }
        cikti.flush()?;
        drop(cikti);
        if yazilan != giris.boyut {
            return Err(Hata::BozukKapsul(format!(
                "'{}' geri yuklendi ama boyutu {yazilan} bayt, ilan edilen {} bayt",
                giris.yol, giris.boyut
            )));
        }
        cikti_bayti += yazilan;
        // Izinler icerik yazildiktan sonra uygulanir; salt-okunur bir dosya
        // acilamayabilirdi.
        if izin_uygula(&yol, giris.izin) {
            izin_uygulanamadi += 1;
        }
    }

    let mut dizin_sayisi = if dizin_agaci { 1u64 } else { 0u64 };
    for (giris, yol) in &olusan_dizinler {
        dizin_sayisi += 1;
        if izin_uygula(yol, giris.izin) {
            izin_uygulanamadi += 1;
        }
    }
    if dizin_agaci && izin_uygula(&kok, 0o755) {
        izin_uygulanamadi += 1;
    }

    Ok(AcRaporu {
        hedef: kok,
        dosya_sayisi: toplam_dosya,
        dizin_sayisi,
        parca_sayisi,
        cikti_bayti,
        kuyruk_ozeti_dogrulandi: secenek.kuyruk_ozetini_dogrula,
        izin_uygulanamadi,
        sure_ms: baslangic.elapsed().as_millis(),
    })
}

/// Kapsül başlığını okur, kuyruk özetini doğrular ve ana anahtarı türetir.
#[allow(clippy::type_complexity)]
pub(crate) fn kapsul_ac(
    kapsul_yolu: &Path,
    parola: &[u8],
    secenek: &AcSecenekleri,
) -> Result<
    (
        SabitBaslik,
        Zeroizing<[u8; ANAHTAR_UZUNLUGU]>,
        [u8; TUZ_UZUNLUGU],
    ),
    Hata,
> {
    let mut dosya = File::open(kapsul_yolu)?;
    let mut kodlu = [0u8; BASLIK_UZUNLUGU];
    dosya
        .read_exact(&mut kodlu)
        .map_err(|_| Hata::BozukKapsul("dosya sabit basliktan kisa".into()))?;
    let baslik = SabitBaslik::coz(&kodlu)?;
    let tuz = SabitBaslik::tuz(&kodlu);
    let gercek_uzunluk = dosya.metadata()?.len();
    if gercek_uzunluk != baslik.kapsul_uzunlugu() {
        return Err(Hata::BozukKapsul(format!(
            "kapsul {gercek_uzunluk} bayt, baslik {} bayt bekliyor",
            baslik.kapsul_uzunlugu()
        )));
    }
    drop(dosya);
    if secenek.kuyruk_ozetini_dogrula {
        kuyruk_ozetini_dogrula(kapsul_yolu, &baslik)?;
    }
    let ayar = Argon2Ayar {
        bellek_kib: baslik.argon2_bellek_kib,
        tur: baslik.argon2_tur,
        yol: baslik.argon2_yol,
    };
    ayar.dogrula()?;
    let malzeme = ana_malzeme_turet(parola, &tuz, &ayar)?;
    let ana_anahtar = alt_anahtar(&malzeme, &tuz, AMAÇ_ANA, 0)?;
    Ok((baslik, ana_anahtar, tuz))
}

/// Kapsül dosyasından şifreli manifest'i çözerek girdi listesini okur.
pub(crate) fn manifest_oku_dosyadan(
    kapsul_yolu: &Path,
    baslik: &SabitBaslik,
    ana_anahtar: &[u8; ANAHTAR_UZUNLUGU],
) -> Result<DizinKaydi, Hata> {
    let mut dosya = File::open(kapsul_yolu)?;
    let mut kodlu = [0u8; BASLIK_UZUNLUGU];
    dosya.seek(SeekFrom::Start(0))?;
    dosya.read_exact(&mut kodlu)?;
    manifest_oku(&mut dosya, baslik, ana_anahtar, &kodlu)
}

/// Dosyanın sonundaki 64 baytlık SHA-512 kuyruk özetini doğrular.
pub fn kuyruk_ozetini_dogrula(kapsul_yolu: &Path, baslik: &SabitBaslik) -> Result<(), Hata> {
    let mut dosya = File::open(kapsul_yolu)?;
    let toplam = baslik.kapsul_uzunlugu();
    if toplam < OZET_UZUNLUGU as u64 {
        return Err(Hata::BozukKapsul(
            "kapsul kuyruk ozeti icin cok kisa".into(),
        ));
    }
    dosya.seek(SeekFrom::Start(0))?;
    let hesaplanan = kapsul_ozeti(&mut dosya, toplam - OZET_UZUNLUGU as u64)?;
    let mut kayitli = [0u8; OZET_UZUNLUGU];
    dosya.read_exact(&mut kayitli)?;
    if ozitler_esit(&hesaplanan, &kayitli) {
        Ok(())
    } else {
        Err(Hata::BozukKapsul(
            "kapsul duzeyinde SHA-512 butunluk ozeti eslesmedi".into(),
        ))
    }
}

/// Kapsülün başlığını ve manifest'ini okuyup özet bilgileri döndürür.
pub fn kapsul_ozeti_oku(kapsul_yolu: &Path, parola: &[u8]) -> Result<KapsulOzeti, Hata> {
    let ac = AcSecenekleri::default();
    let (baslik, ana_anahtar, _) = kapsul_ac(kapsul_yolu, parola, &ac)?;
    let manifest = manifest_oku_dosyadan(kapsul_yolu, &baslik, &ana_anahtar)?;
    let girdi_bayti = manifest.toplam_bayt();
    let yuk = manifest.payload_uzunlugu().saturating_sub(girdi_bayti);
    let etik_yuku_yuzdesi = if girdi_bayti == 0 {
        0.0
    } else {
        (yuk as f64 / girdi_bayti as f64) * 100.0
    };
    Ok(KapsulOzeti {
        surum: crate::kapsul::SURUM,
        parca_boyutu: baslik.parca_boyutu,
        argon2: Argon2Ayar {
            bellek_kib: baslik.argon2_bellek_kib,
            tur: baslik.argon2_tur,
            yol: baslik.argon2_yol,
        },
        dizin_agaci: baslik.dizin_agaci(),
        kok_ad: manifest.kok_ad.clone(),
        girdi_sayisi: manifest.girdiler.len() as u64,
        parca_sayisi: manifest.parca_sayisi(),
        girdi_bayti,
        kapsul_bayti: baslik.kapsul_uzunlugu(),
        etik_yuku_yuzdesi,
        kuyruk_ozeti_dogrulandi: true,
    })
}

#[cfg(unix)]
fn izin_uygula(yol: &Path, modu: u32) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(yol, std::fs::Permissions::from_mode(modu & 0o7777)).is_err()
}

#[cfg(not(unix))]
fn izin_uygula(yol: &Path, modu: u32) -> bool {
    // NTFS ACL'leri `std` ile yazilamaz (`unsafe`/FFI yasak) ve Windows'un
    // `PermissionsExt` uzantisi bu toolchain'de kararsiz (`windows_permissions_ext`).
    // Bu yuzden izin geri yuklemesi bu platformda **yapilmaz** ve cagrilana
    // durum `true` olarak bildirilir; boylece cagiran eksikligi olcum edebilir.
    let _ = (yol, modu);
    true
}

#[cfg(test)]
// `unwrap`/`expect` testlerde kabul edilir (WORKER_CONTRACT §4.2).
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::kapsul::EN_KUCUK_PARCA;
    use std::collections::HashSet;
    use std::fs;

    struct GeciciDizin {
        yol: PathBuf,
    }

    impl GeciciDizin {
        fn yeni(etiket: &str) -> Self {
            let kok = std::env::temp_dir()
                .join(format!("sealedbox-akis-{etiket}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&kok);
            fs::create_dir_all(&kok).unwrap();
            GeciciDizin { yol: kok }
        }

        fn birles(&self, ad: &str) -> PathBuf {
            self.yol.join(ad)
        }

        fn yaz(&self, ad: &str, icerik: &[u8]) -> PathBuf {
            let yol = self.birles(ad);
            if let Some(ebeveyn) = yol.parent() {
                fs::create_dir_all(ebeveyn).unwrap();
            }
            fs::write(&yol, icerik).unwrap();
            yol
        }
    }

    impl Drop for GeciciDizin {
        fn drop(&mut self) {
            // `Drop` icinden hata dondurulemez; temizlik basarisiz olsa da testi
            // dusurmemelidir (WORKER_CONTRACT §5.3).
            let _ = fs::remove_dir_all(&self.yol);
        }
    }

    fn hizli() -> MuhurSecenekleri {
        MuhurSecenekleri {
            parca_boyutu: EN_KUCUK_PARCA,
            argon2: Argon2Ayar {
                bellek_kib: 16_384,
                tur: 1,
                yol: 1,
            },
            ..MuhurSecenekleri::default()
        }
    }

    /// Kapsüldeki tüm parça nonce'larını okur.
    fn tum_nonce_lar(kapsul: &Path, parola: &[u8]) -> Vec<[u8; NONCE_UZUNLUGU]> {
        let secenek = AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        };
        let (baslik, ana_anahtar, _) = kapsul_ac(kapsul, parola, &secenek).unwrap();
        let kayit = manifest_oku_dosyadan(kapsul, &baslik, &ana_anahtar).unwrap();
        kayit
            .girdiler
            .iter()
            .flat_map(|giris| giris.parcalar.iter().map(|p| p.nonce))
            .collect()
    }

    #[test]
    fn kapsul_ici_tum_nonce_lar_tekildir() {
        let gecici = GeciciDizin::yeni("nonce-tekil");
        let parola = b"nonce testi";
        gecici.yaz("agac/a.bin", &vec![7u8; 2 * EN_KUCUK_PARCA as usize]);
        gecici.yaz("agac/b.bin", &vec![9u8; EN_KUCUK_PARCA as usize + 3]);
        let kapsul = gecici.birles("agac.sbx");
        muhurle(&gecici.birles("agac"), &kapsul, parola, &hizli()).unwrap();

        let nonce_lar = tum_nonce_lar(&kapsul, parola);
        assert_eq!(nonce_lar.len(), 4, "3 + 2 parca bekleniyordu");
        let benzersiz: HashSet<[u8; NONCE_UZUNLUGU]> = nonce_lar.iter().copied().collect();
        assert_eq!(
            benzersiz.len(),
            nonce_lar.len(),
            "hicbir parca nonce'u tekrar etmemeli"
        );
    }

    #[test]
    fn iki_kapsulun_nonce_lari_ortusmaz() {
        let gecici = GeciciDizin::yeni("nonce-ortusme");
        let parola = b"nonce testi";
        gecici.yaz("a.bin", &vec![1u8; EN_KUCUK_PARCA as usize * 2]);
        let bir = gecici.birles("bir.sbx");
        let iki = gecici.birles("iki.sbx");
        muhurle(&gecici.birles("a.bin"), &bir, parola, &hizli()).unwrap();
        muhurle(&gecici.birles("a.bin"), &iki, parola, &hizli()).unwrap();
        let bir_nonce = tum_nonce_lar(&bir, parola);
        let iki_nonce = tum_nonce_lar(&iki, parola);
        let kesisim: HashSet<_> = bir_nonce.iter().filter(|n| iki_nonce.contains(n)).collect();
        assert!(
            kesisim.is_empty(),
            "farkli kapsullarda nonce paylasilmamali"
        );
    }

    #[test]
    fn kotu_niyetli_manifest_yolu_cozmede_reddedilir() {
        // Saldirgan elinde dogru anahtar varsa (ozellikle diskteki kapsulu
        // duzenleyebiliyorsa) manifest'e `../` yazabilir. Bu yolun **cozme
        // aninda**, dosya sistemine hic dokunulmadan reddedildigi kanitlanir.
        let gecici = GeciciDizin::yeni("kotu-manifest");
        let parola = b"saldirgan testi";
        gecici.yaz("agac/iyi.txt", b"veri");
        let kapsul = gecici.birles("agac.sbx");
        muhurle(&gecici.birles("agac"), &kapsul, parola, &hizli()).unwrap();

        let secenek = AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        };
        let (baslik, ana_anahtar, _) = kapsul_ac(&kapsul, parola, &secenek).unwrap();
        let kayit = manifest_oku_dosyadan(&kapsul, &baslik, &ana_anahtar).unwrap();

        let mut kotu = kayit.clone();
        // Saldırganın yazdığı yol **aynı uzunlukta** olmalıdır: manifest bloğunun
        // uzunluğu başlıkta sabitlendiği için başka uzunlukta bir yazım kapsül
        // düzenini bozardı ve test yanlış nedeni ölçerdi.
        let ornek_yol = kotu.girdiler[0].yol.clone();
        let mut kotu_yol = String::from("../");
        kotu_yol.push_str(&"x".repeat(ornek_yol.len() - 3));
        assert_eq!(kotu_yol.len(), ornek_yol.len());
        kotu.girdiler[0].yol = kotu_yol;

        // Kotu manifest'i ayni anahtarla yeniden sifrele: etik gecerli olur,
        // boylece test yalnizca yol denetlemini olcer.
        let mut kodlu_baslik = [0u8; BASLIK_UZUNLUGU];
        fs::File::open(&kapsul)
            .unwrap()
            .read_exact(&mut kodlu_baslik)
            .unwrap();
        let mut duz = Zeroizing::new(kotu.kodla());
        let etiket = manifest_sifrele(
            &ana_anahtar,
            &baslik.manifest_nonce,
            SabitBaslik::aad(&kodlu_baslik),
            duz.as_mut_slice(),
        )
        .unwrap();
        {
            let mut dosya = OpenOptions::new().write(true).open(&kapsul).unwrap();
            dosya.seek(SeekFrom::Start(BASLIK_UZUNLUGU as u64)).unwrap();
            dosya.write_all(&duz).unwrap();
            dosya.write_all(&etiket).unwrap();
        }

        let hedef = gecici.birles("hedef");
        let hata = ac(&kapsul, &hedef, parola, &secenek).unwrap_err();
        assert!(
            matches!(hata, Hata::GecersizYol(_)),
            "yol denetlenmeliydi, alinan: {hata:?}"
        );
        assert!(!gecici.birles("disarida.txt").exists());
    }

    #[test]
    fn parca_tamponu_sabit_kapasitededir() {
        // Bellek sabit tampon vaadinin mekanizma denetimi: tampon kapasitesi
        // parca boyutuna esittir ve okuma sayisi arttikca degismez.
        let parca = EN_KUCUK_PARCA as usize;
        let mut tampon = Zeroizing::new(vec![0u8; parca]);
        let baslangic_kapasite = tampon.capacity();
        assert_eq!(baslangic_kapasite, parca);
        // Tamponun 4 katı boyutunda bir kaynak: tampona asla tamponun
        // kendisinden fazlası sığmamalı.
        let sahte = std::io::Cursor::new(vec![0x5Au8; parca * 4]);
        let mut okuyucu = std::io::BufReader::new(sahte);
        for _ in 0..4 {
            let okunan = tam_doldur(&mut okuyucu, tampon.as_mut_slice()).unwrap();
            assert_eq!(okunan, parca);
            assert_eq!(tampon.capacity(), baslangic_kapasite);
        }
        // Tampon kullanildiktan sonra zeroize ile temizlenebilir.
        use zeroize::Zeroize;
        tampon.zeroize();
        assert!(tampon.iter().all(|b| *b == 0));
    }

    #[test]
    fn yarim_yazilmis_kapsul_acilmaz() {
        let gecici = GeciciDizin::yeni("yarim-kapsul");
        let parola = b"yarim testi";
        gecici.yaz("a.bin", &[3u8; 5_000]);
        let kapsul = gecici.birles("a.sbx");
        let hata = muhurle(
            &gecici.birles("a.bin"),
            &kapsul,
            parola,
            &MuhurSecenekleri {
                devam: true,
                ilerleme: Some(Arc::new(|i: Ilerleme| {
                    if i.asama == "sifreleniyor" {
                        return Err(Hata::Iptal);
                    }
                    Ok(())
                })),
                ..hizli()
            },
        )
        .unwrap_err();
        assert!(matches!(hata, Hata::Iptal));
        assert!(!kapsul.exists());

        // Ana kapsul olmadigi icin acma basarisiz.
        let secenek = AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        };
        assert!(ac(&kapsul, &gecici.birles("g"), parola, &secenek).is_err());
    }

    #[test]
    fn kapsul_ozeti_oge_parca_boyutunu_bildirir() {
        let gecici = GeciciDizin::yeni("ozet-oge");
        let parola = b"ozet testi";
        gecici.yaz("a.bin", &[4u8; 1_000]);
        let kapsul = gecici.birles("a.sbx");
        muhurle(&gecici.birles("a.bin"), &kapsul, parola, &hizli()).unwrap();
        let ozet = kapsul_ozeti_oku(&kapsul, parola).unwrap();
        assert_eq!(ozet.parca_boyutu, EN_KUCUK_PARCA);
        assert_eq!(ozet.parca_sayisi, 1);
        assert_eq!(ozet.girdi_bayti, 1_000);
        // Tek parca: yuk = 32 bayt / 1000 bayt = %3.2
        assert!(
            (ozet.etik_yuku_yuzdesi - 3.2).abs() < 0.001,
            "{}",
            ozet.etik_yuku_yuzdesi
        );
    }

    #[test]
    fn kapsul_ozeti_hatali_parolada_basarisiz_olur() {
        let gecici = GeciciDizin::yeni("ozet-hata");
        gecici.yaz("a.bin", &[4u8; 100]);
        let kapsul = gecici.birles("a.sbx");
        muhurle(&gecici.birles("a.bin"), &kapsul, b"dogru", &hizli()).unwrap();
        assert!(kapsul_ozeti_oku(&kapsul, b"yanlis").is_err());
    }
}
