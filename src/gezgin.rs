//! Klasör ağacı gezgini.
//!
//! `walkdir` bağımlılığı yasaklıdır (WORKER_CONTRACT §3.2-F), bu yüzden
//! özyinelemeli `read_dir` gezintisi burada kendi kodumuzla yazılır. Modülün
//! sorumluluğu yalnızca "hangi dosyalar var, boyutları/izinleri/zaman
//! damgaları ne" sorusunu yanıtlamaktır; şifreleme burada yapılmaz.
//!
//! Simge bağları (sembolik bağ) **atlanır**: bir kapsülün çözülmesi hedef
//! ağacın dışına çıkan bir bağı takip etmemelidir.

use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use crate::dizin::{yolu_dogrula, Tur};
use crate::hata::Hata;

/// Gezginin ürettiği tek bir kayıt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kayit {
    /// Kaynak köke göreli yol, `/` ile ayrılmış.
    pub goreli_yol: String,
    /// Dosya mı dizin mi.
    pub tur: Tur,
    /// Dosya boyutu (bayt); dizinlerde `0`.
    pub boyut: u64,
    /// Saklanacak izin bitleri.
    pub izin: u32,
    /// Değişiklik zamanı (Unix saniyesi).
    pub mtime_saniye: i64,
    /// Değişiklik zamanının nanosaniye kısmı.
    pub mtime_nano: u32,
}

/// Bir kaynağın taranmış hâli.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Taranmis {
    /// Kaynak bir klasör ağacı mıydı.
    pub dizin_agaci: bool,
    /// Kapsül kökünün adı (tek dosyada dosya adı).
    pub kok_ad: String,
    /// Yola göre sıralanmış kayıtlar; dizin girdisi kök için **yoktur**.
    pub kayitlar: Vec<Kayit>,
}

/// Kaynağı özyinelemeli olarak tarar ve yola göre sıralanmış kayıt listesi döndürür.
///
/// Sıralama determinizmi sağlar: aynı girdi kümesi her zaman aynı manifest
/// baytlarını üretir. Üst dizinler, alt girdilerinden önce gelir; geri
/// yükleme sırasında bu sıralama gereklidir.
pub fn tara(kaynak: &Path) -> Result<Taranmis, Hata> {
    let kok_ad = kaynak
        .file_name()
        .map(|ad| ad.to_string_lossy().to_string())
        .ok_or_else(|| Hata::BozukArguman("kaynak yolunun adi yok".into()))?;
    yolu_dogrula(&kok_ad)?;

    let meta = fs::metadata(kaynak)?;
    if meta.is_dir() {
        let mut kayitlar = Vec::new();
        dizini_tara(kaynak, "", &mut kayitlar, 0)?;
        kayitlar.sort_by(|a, b| a.goreli_yol.cmp(&b.goreli_yol));
        Ok(Taranmis {
            dizin_agaci: true,
            kok_ad,
            kayitlar,
        })
    } else if meta.is_file() {
        Ok(Taranmis {
            dizin_agaci: false,
            kok_ad: kok_ad.clone(),
            kayitlar: vec![Kayit {
                goreli_yol: kok_ad,
                tur: Tur::Dosya,
                boyut: meta.len(),
                izin: izin_modu(&meta),
                mtime_saniye: mtime_saniye(&meta),
                mtime_nano: mtime_nano(&meta),
            }],
        })
    } else {
        Err(Hata::BozukArguman(format!(
            "'{}' duzenli dosya veya dizin degil",
            kaynak.display()
        )))
    }
}

const AZAMI_DERINLIK: usize = 64;

fn dizini_tara(
    dizin: &Path,
    onek: &str,
    cikti: &mut Vec<Kayit>,
    derinlik: usize,
) -> Result<(), Hata> {
    if derinlik > AZAMI_DERINLIK {
        return Err(Hata::BozukArguman(format!(
            "dizin agaci {AZAMI_DERINLIK} seviyeyi asiyor"
        )));
    }
    let mut adlar: Vec<String> = Vec::new();
    for giris in fs::read_dir(dizin)? {
        let giris = giris?;
        adlar.push(giris.file_name().to_string_lossy().to_string());
    }
    // read_dir siralamasi platforma bagimlidir; determinizm icin siraliyoruz.
    adlar.sort();

    for ad in adlar {
        let tam_yol = dizin.join(&ad);
        let goreli = if onek.is_empty() {
            ad.clone()
        } else {
            format!("{onek}/{ad}")
        };
        yolu_dogrula(&goreli)?;
        // Simge baglari takip edilmez: hedef agacin disina cikmamali.
        let meta = match fs::symlink_metadata(&tam_yol) {
            Ok(m) => m,
            Err(hata) if hata.kind() == std::io::ErrorKind::NotFound => continue,
            Err(hata) => return Err(Hata::Io(hata)),
        };
        let tur = if meta.file_type().is_symlink() {
            continue;
        } else if meta.is_dir() {
            Tur::Dizin
        } else if meta.is_file() {
            Tur::Dosya
        } else {
            continue;
        };
        cikti.push(Kayit {
            goreli_yol: goreli.clone(),
            tur,
            boyut: if tur == Tur::Dosya { meta.len() } else { 0 },
            izin: izin_modu(&meta),
            mtime_saniye: mtime_saniye(&meta),
            mtime_nano: mtime_nano(&meta),
        });
        if tur == Tur::Dizin {
            dizini_tara(&tam_yol, &goreli, cikti, derinlik + 1)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn izin_modu(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn izin_modu(meta: &fs::Metadata) -> u32 {
    // Windows'ta std yalnızca salt-okunur bitini döndürebilir; NTFS ACL'leri
    // `unsafe`/FFI olmadan yazılamaz, bu yüzden kapsam bilinçli olarak daraltıldı.
    if meta.permissions().readonly() {
        0o444
    } else {
        0o666
    }
}

fn mtime_saniye(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|zaman| zaman.duration_since(UNIX_EPOCH).ok())
        .map(|fark| fark.as_secs() as i64)
        .unwrap_or(0)
}

fn mtime_nano(meta: &fs::Metadata) -> u32 {
    meta.modified()
        .ok()
        .and_then(|zaman| zaman.duration_since(UNIX_EPOCH).ok())
        .map(|fark| fark.subsec_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
// `unwrap`/`expect` testlerde kabul edilir (WORKER_CONTRACT §4.2).
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Test içinde geçici dizin üreten, Drop ile temizleyen kapsayıcı.
    ///
    /// Neden `tempfile` yok: bağımlılık politikası (WORKER_CONTRACT §3.2) onu
    /// hiçbir projede vermez. `Drop` içinden hata döndürülemediği için temizlik
    /// hatası `let _ =` ile bilinçli olarak yutulur.
    struct GeciciDizin {
        yol: PathBuf,
    }

    impl GeciciDizin {
        fn yeni(etiket: &str) -> Self {
            let kok =
                std::env::temp_dir().join(format!("sealedbox-{etiket}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&kok);
            fs::create_dir_all(&kok).expect("gecici dizin olusturulamadi");
            GeciciDizin { yol: kok }
        }

        fn yol(&self) -> &Path {
            &self.yol
        }
    }

    impl Drop for GeciciDizin {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.yol);
        }
    }

    fn yaz(yol: &Path, icerik: &[u8]) {
        if let Some(ebeveyn) = yol.parent() {
            fs::create_dir_all(ebeveyn).expect("dizin olusturulamadi");
        }
        fs::write(yol, icerik).expect("dosya yazilamadi");
    }

    #[test]
    fn tek_dosya_taranir_ve_kok_adi_dosya_adi_olur() {
        let gecici = GeciciDizin::yeni("tek-dosya");
        let dosya = gecici.yol().join("rapor.txt");
        yaz(&dosya, b"merhaba");
        let taranmis = tara(&dosya).unwrap();
        assert!(!taranmis.dizin_agaci);
        assert_eq!(taranmis.kok_ad, "rapor.txt");
        assert_eq!(taranmis.kayitlar.len(), 1);
        assert_eq!(taranmis.kayitlar[0].boyut, 7);
        assert_eq!(taranmis.kayitlar[0].tur, Tur::Dosya);
    }

    #[test]
    fn ic_ice_dizinler_ve_bos_dizin_taranir() {
        let gecici = GeciciDizin::yeni("ic-ice");
        let kok = gecici.yol().join("agac");
        yaz(&kok.join("a/b/c/derin.txt"), b"0123456789");
        yaz(&kok.join("ust.txt"), b"x");
        fs::create_dir_all(kok.join("bos")).unwrap();
        let taranmis = tara(&kok).unwrap();
        assert!(taranmis.dizin_agaci);
        let yollar: Vec<&str> = taranmis
            .kayitlar
            .iter()
            .map(|k| k.goreli_yol.as_str())
            .collect();
        assert_eq!(
            yollar,
            vec!["a", "a/b", "a/b/c", "a/b/c/derin.txt", "bos", "ust.txt"]
        );
        let bos = taranmis
            .kayitlar
            .iter()
            .find(|k| k.goreli_yol == "bos")
            .unwrap();
        assert_eq!(bos.tur, Tur::Dizin);
        assert_eq!(bos.boyut, 0);
    }

    #[test]
    fn tarama_sirali_ve_deterministiktir() {
        let gecici = GeciciDizin::yeni("determinizm");
        let kok = gecici.yol().join("agac");
        for ad in ["z.txt", "a.txt", "m.txt"] {
            yaz(&kok.join(ad), b"i");
        }
        let bir = tara(&kok).unwrap();
        let iki = tara(&kok).unwrap();
        assert_eq!(bir, iki, "iki tarama ayni sonucu vermeli");
        let yollar: Vec<&str> = bir.kayitlar.iter().map(|k| k.goreli_yol.as_str()).collect();
        assert_eq!(yollar, vec!["a.txt", "m.txt", "z.txt"]);
    }

    #[test]
    fn bos_dizin_taramasi_bos_liste_dondurur() {
        let gecici = GeciciDizin::yeni("bos-agac");
        let kok = gecici.yol().join("agac");
        fs::create_dir_all(&kok).unwrap();
        let taranmis = tara(&kok).unwrap();
        assert!(taranmis.dizin_agaci);
        assert!(taranmis.kayitlar.is_empty());
    }

    #[test]
    fn olmayan_kaynak_hata_dondurur() {
        let gecici = GeciciDizin::yeni("yok");
        let yok = gecici.yol().join("olmayan");
        assert!(matches!(tara(&yok), Err(Hata::Io(_))));
    }

    #[cfg(unix)]
    #[test]
    fn simge_baglari_atlanir() {
        use std::os::unix::fs::symlink;
        let gecici = GeciciDizin::yeni("simge");
        let kok = gecici.yol().join("agac");
        yaz(&kok.join("gercek.txt"), b"gercek");
        yaz(&gecici.yol().join("dis.txt"), b"dis");
        symlink(gecici.yol().join("dis.txt"), kok.join("bag.txt")).unwrap();
        let taranmis = tara(&kok).unwrap();
        let yollar: Vec<&str> = taranmis
            .kayitlar
            .iter()
            .map(|k| k.goreli_yol.as_str())
            .collect();
        assert_eq!(yollar, vec!["gercek.txt"], "simge bagi takip edilmemeli");
    }
}
