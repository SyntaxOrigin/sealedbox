//! Hata tipi ve nedenleri.
//!
//! Bu modül kapsül okuma/yazma sırasında oluşabilecek tüm hataları tek bir
//! [`Hata`] enum'unda toplar. Modülün sorumluluğu hatanın *ne olduğunu* taşımaktır;
//! hangi durumda üretileceği ilgili modüllerin (`kapsul`, `dizin`, `kripto`,
//! `akis`) işidir.
//!
//! Güvenlik kuralı: hiçbir `Display` metni parola, anahtar veya şifre metni
//! içermez. Manifest doğrulaması başarısız olduğunda "parola yanlış" ile
//! "manifest bozuk" ayrımı **yapılmaz**; kriptografik olarak imkânsızdır.
//! Buna karşılık bir *parça* etiketi başarısızlığı yalnızca manifest
//! doğrulandıktan sonra bildirilebilir, dolayısıyla parçanın konumu güvenle
//! raporlanabilir: o noktaya gelindiğinde parolanın doğru olduğu kanıtlanmıştır.

use std::error::Error;
use std::fmt;
use std::io;

/// `sealedbox` çekirdeğinin ürettiği tüm hataları kapsayan tip.
///
/// `Display` uygulaması elle yazılmıştır; `thiserror` gibi bir bağımlılık
/// bu projede yasaktır (WORKER_CONTRACT §3.2).
#[derive(Debug)]
#[non_exhaustive]
pub enum Hata {
    /// Dosya sistemi işlemi başarısız oldu.
    Io(io::Error),
    /// Kapsül başlığı, manifest veya kuyruk özeti okunamadı/doğrulanamadı.
    ///
    /// Bu varyant parola yanlışlığını da kapsar ve mesajı bunu **açıkça
    /// ayırt etmez**.
    BozukKapsul(String),
    /// Bir parçanın Poly1305 etiketi doğrulanamadı.
    ///
    /// Parça konumu güvenle raporlanabilir: manifest önceden doğrulandığı için
    /// parolanın doğru olduğu bu noktada kanıtlanmıştır.
    BozukParca {
        /// Etiketi doğrulanamayan parçanın sırası (0 tabanlı).
        parca: u64,
        /// Parçanın ait olduğu dosyanın kapsül içi yolu.
        dosya: String,
    },
    /// Kapsül içindeki yol güvenli değil (mutlak, `..` içeren, ayraç içeren).
    GecersizYol(String),
    /// Hedef zaten var; üzerine yazma varsayılan olarak reddedilir.
    VarOluyor(String),
    /// Komut satırı ya da API çağrısı geçersiz bir değer verdi.
    BozukArguman(String),
    /// Kriptografik işlem (türetme, şifreleme, çözme) başarısız oldu.
    Kriptografik(String),
    /// Kullanıcı ilerleme geri çağrısı ile işi iptal etti.
    Iptal,
}

impl fmt::Display for Hata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Hata::Io(hata) => write!(f, "dosya sistemi hatasi: {hata}"),
            Hata::BozukKapsul(detay) => write!(
                f,
                "parola yanlis veya kapsul butunlugu bozuk{sep}",
                sep = if detay.is_empty() {
                    String::new()
                } else {
                    format!(" ({detay})")
                }
            ),
            Hata::BozukParca { parca, dosya } => {
                write!(f, "parca etigi dogrulanmadi: '{dosya}' parcasi #{parca}")
            }
            Hata::GecersizYol(yol) => write!(
                f,
                "gecersiz kapsul yolu: '{yol}' (mutlak yol, '..' veya ayrac icermemeli)"
            ),
            Hata::VarOluyor(yol) => write!(
                f,
                "'{yol}' zaten var; uzerine yazmak icin --ustune-yaz kullanin"
            ),
            Hata::BozukArguman(detay) => write!(f, "gecersiz arguman: {detay}"),
            Hata::Kriptografik(detay) => write!(f, "kriptografik hata: {detay}"),
            Hata::Iptal => write!(f, "islem kullanici tarafindan iptal edildi"),
        }
    }
}

impl Error for Hata {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Hata::Io(hata) => Some(hata),
            _ => None,
        }
    }
}

impl From<io::Error> for Hata {
    fn from(hata: io::Error) -> Self {
        Hata::Io(hata)
    }
}
