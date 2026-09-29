//! MühürKasa (SealedBox) — akış hâlinde AES-256-GCM ile büyük dosya ve
//! klasör ağacı mühürleme kütüphanesi.
//!
//! # Kapsam
//!
//! Kapsül, tek bir dosyada şu düzeni kullanır (`SBX1` sürüm 1):
//!
//! ```text
//! [96 bayt sabit baslik (duz metin)]
//! [sifreli manifest: yollar, boyutlar, izinler, parca tablosu + 16 bayt etiket]
//! [parca govleri: nonce(12) | uzunluk(4) | sifre metni | etiket(16)]
//! [64 bayt SHA-512 kuyruk ozeti]
//! ```
//!
//! Gövde **sabit boyutlu tamponla** akıtılır: bir dosyanın tamamı belleğe
//! asla alınmaz. Bellek tüketimi dosya boyutundan bağımsızdır; tek dosya boyutu
//! ile değişen tek şey manifest'tir (dosya sayısı ve parça sayısı ile ölçeklenir).
//!
//! # Kriptografik sözleşme
//!
//! - Parola → Argon2id (RFC 9106) → ana malzeme.
//! - Ana malzeme → HKDF-SHA256 → ana anahtar; ana anahtar → HKDF-SHA256 →
////!   **her dosya için ayrı** alt anahtar.
//! - Her parça, kendi alt anahtarıyla AES-256-GCM (NIST SP 800-38D) kullanır ve
//!   96-bit nonce'u `getrandom` ile **rastgele** üretilir; nonce asla sayaç değildir.
//! - Her parçanın ek verisi (dosya sırası ‖ parça sırası) parçayı kapsüldeki
//!   konumuna bağlar; yer değiştirme ve kesme saldırıları etik doğrulamasında
//!   yakalanır.
//! - Anahtar ve düz metin tamponları `zeroize` ile sıfırlanır.
//!
//! # Örnek
//!
//! ```no_run
//! use sealedbox::akis::{muhurle, MuhurSecenekleri};
//! use std::path::Path;
//!
//! let secenek = MuhurSecenekleri::default();
//! let rapor = muhurle(
//!     Path::new("./veri"),
//!     Path::new("./veri.sbx"),
//!     b"parola",
//!     &secenek,
//! )?;
//! println!("{} parca yazildi", rapor.parca_sayisi);
//! # Ok::<(), sealedbox::hata::Hata>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::unwrap_used, clippy::expect_used)]

pub mod akis;
pub mod dizin;
pub mod dogrulama;
pub mod gezgin;
pub mod hata;
pub mod kapsul;
pub mod kripto;

pub use akis::{
    ac, kapsul_ozeti_oku, kuyruk_ozetini_dogrula, muhurle, AcRaporu, AcSecenekleri, Ilerleme,
    KapsulOzeti, MuhurRaporu, MuhurSecenekleri,
};
pub use dogrulama::{dogrula, DogrulamaRaporu};
pub use hata::Hata;
pub use kapsul::SabitBaslik;
pub use kripto::Argon2Ayar;
