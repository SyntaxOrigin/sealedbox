//! Entegrasyon testleri için ortak yardımcılar.
//!
//! `tempfile` crate'i bağımlılık politikası gereği yasaktır
//! (WORKER_CONTRACT §3.2), bu yüzden geçici dizin üretimi ve temizliği kendi
//! kodumuzla yapılır. Benzersizlik `std::process::id()` ve etiketten türetilir;
//! rastgelelik crate'i kullanılmaz.
//!
//! `Drop` içinden hata döndürülemediği için temizlik hatası `let _ =` ile
//! bilinçli olarak yutulur; bu, sözleşmenin "sessiz yutma" yasağına yegdir
//! (WORKER_CONTRACT §5.3) ve README'de belgelenmiştir.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sealedbox::Argon2Ayar;

/// Testlerde kullanılan Argon2id parametreleri.
///
/// Varsayılan (64 MiB / 3 tur / 4 yol) her çağrıda ~50 ms sürer ve test
/// süresini gereksiz uzatır. Buradaki değerler `Argon2Ayar::dogrula` sınırları
/// içindedir; kriptografik parametrelerin doğru taşındığı ayrıca birim testlerde
/// sınanır.
pub fn hizli_argon2() -> Argon2Ayar {
    Argon2Ayar {
        bellek_kib: 16_384,
        tur: 1,
        yol: 1,
    }
}

static SAYAC: AtomicU64 = AtomicU64::new(0);

/// Drop ile temizlenen geçici dizin kapsayıcısı.
pub struct GeciciDizin {
    yol: PathBuf,
}

impl GeciciDizin {
    /// `std::env::temp_dir()` altında benzersiz bir dizin oluşturur.
    pub fn yeni(etiket: &str) -> Self {
        let sira = SAYAC.fetch_add(1, Ordering::Relaxed);
        let kok = std::env::temp_dir().join(format!(
            "sealedbox-test-{etiket}-{}-{sira}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&kok);
        fs::create_dir_all(&kok).expect("gecici dizin olusturulamadi");
        GeciciDizin { yol: kok }
    }

    /// Dizinin tam yolu.
    pub fn yol(&self) -> &Path {
        &self.yol
    }

    /// Alt dosya yolu.
    pub fn birles(&self, ad: &str) -> PathBuf {
        self.yol.join(ad)
    }

    /// Alt dosyayı oluşturup içeriğini yazar (üst dizinler dâhil).
    pub fn yaz(&self, ad: &str, icerik: &[u8]) -> PathBuf {
        let yol = self.birles(ad);
        if let Some(ebeveyn) = yol.parent() {
            fs::create_dir_all(ebeveyn).expect("ust dizin olusturulamadi");
        }
        fs::write(&yol, icerik).expect("dosya yazilamadi");
        yol
    }

    /// Alt dizin oluşturur.
    pub fn dizin(&self, ad: &str) -> PathBuf {
        let yol = self.birles(ad);
        fs::create_dir_all(&yol).expect("dizin olusturulamadi");
        yol
    }
}

impl Drop for GeciciDizin {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.yol);
    }
}

/// Test verisi üretir: `tohum` değerine göre tekrarlanabilir (deterministik) baytlar.
pub fn veri(bayt: usize, tohum: u8) -> Vec<u8> {
    (0..bayt)
        .map(|i| tohum.wrapping_add((i % 251) as u8))
        .collect()
}

/// Bayt dizisini hex'e çevirir (hata mesajlarında kullanılır).
pub fn hex(bayt: &[u8]) -> String {
    bayt.iter().map(|b| format!("{b:02x}")).collect()
}

/// Bir dizin ağacının tam dökümü: göreli yol → (bayt, salt-okunur bayrağı).
///
/// **Veri güvenliği testlerinin temel aracıdır.** Bir komut hata döndürdükten
/// sonra bu dökümün **boş** kaldığını kanıtlamak, o komutun diskte yarım bir
/// çıktı bırakmadığını gösterir. Boyut *ve* izin birlikte karşılaştırılır;
/// aksi halde "içerik silindi ama boş dosya kaldı" gibi sinsi artıklar görünmez.
pub fn agac_dokumu(kok: &Path) -> BTreeMap<String, (u64, bool)> {
    let mut harita = BTreeMap::new();
    let mut yigin: Vec<PathBuf> = vec![kok.to_path_buf()];
    while let Some(dizin) = yigin.pop() {
        let Ok(girdiler) = fs::read_dir(&dizin) else {
            continue;
        };
        for giris in girdiler.flatten() {
            let yol = giris.path();
            let goreli = yol
                .strip_prefix(kok)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| yol.to_string_lossy().into_owned());
            let Ok(meta) = fs::symlink_metadata(&yol) else {
                continue;
            };
            if meta.is_dir() {
                harita.insert(goreli.clone(), (0, meta.permissions().readonly()));
                yigin.push(yol);
            } else {
                harita.insert(goreli, (meta.len(), meta.permissions().readonly()));
            }
        }
    }
    harita
}
