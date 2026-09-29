//! Kapsül sabit başlığı: biçim sabitleri, serileştirme ve ayrıştırma.
//!
//! Bu modül kapsül dosyasının **düz metin** kısmıyla ilgilenir; şifreli bölümler
//! (`dizin` ve `kripto` modülleri) burada yalnızca uzunluk alanları üzerinden
//! konumlanır. Modül dosya sistemi erişimi yapmaz; yalnızca bayt dizileriyle
//! çalışır, böylece test vektörleri diske ihtiyaç duymadan yazılabilir.
//!
//! Başlık 96 bayttır. `[0..64]` aralığı **değişmezdir** ve AES-GCM ek verisi
//! (AAD) olarak kullanılır. `[64..96]` aralığı mühürleme sırasında güncellenir;
//! bu ayrım "kaldığı yerden devam" özelliğini mümkün kılar.

use crate::hata::Hata;

/// Kapsül sihirli sayısı; ilk dört bayt.
pub const SIHRLI: [u8; 4] = *b"SBX1";
/// Desteklenen kapsül biçimi sürümü.
pub const SURUM: u8 = 1;
/// Sabit başlığın toplam uzunluğu (bayt).
pub const BASLIK_UZUNLUGU: usize = 96;
/// AES-GCM ek verisi (AAD) olarak kullanılan değişmez önek uzunluğu.
pub const AAD_UZUNLUGU: usize = 64;
/// Tu uzunluğu (bayt).
pub const TUZ_UZUNLUGU: usize = 16;
/// Parça nonce uzunluğu (bayt); GCM için standart 96-bit.
pub const NONCE_UZUNLUGU: usize = 12;
/// Poly1305 etiket uzunluğu (bayt).
pub const ETIKET_UZUNLUGU: usize = 16;
/// Kuyruk özeti uzunluğu (bayt): SHA-512.
pub const OZET_UZUNLUGU: usize = 64;
/// En küçük kabul edilen parça boyutu (bayt) — rapor b10 alt sınırı.
pub const EN_KUCUK_PARCA: u32 = 512 * 1024;
/// En büyük kabul edilen parça boyutu (bayt) — rapor b10 üst sınırı.
pub const EN_BUYUK_PARCA: u32 = 8 * 1024 * 1024;
/// Varsayılan parça boyutu (bayt): 2 MiB.
pub const VARSAYILAN_PARCA: u32 = 2 * 1024 * 1024;
/// En büyük Argon2 bellek maliyeti (KiB) — rapor b10 üst sınırı.
pub const EN_FAZLA_BELLEK_KIB: u32 = 262_144;
/// En küçük Argon2 bellek maliyeti (KiB) — rapor b10 alt sınırı.
pub const EN_AZ_BELLEK_KIB: u32 = 16_384;

/// Bayrak: kapsül bir klasör ağacını içerir (tek dosya değil).
pub const BAYRAK_DIZIN: u8 = 0b0000_0001;

/// `durum` alanı: kapsül tamamen yazıldı.
///
/// Yazma durumu **bayraklarda değil** bu alandadır. Nedeni: başlığın `[0..64]`
/// öneki AES-GCM ek verisi (AAD) olarak kullanılır ve mühürleme boyunca
/// **değişmez** olmalıdır. Bayraklara "yazılıyor" biti koysaydık, mühürleme
/// sonunda bu biti temizlemek AAD'yi değiştirir ve manifest etiketi bozulurdu.
pub const DURUM_TAMAM: u32 = 0;
/// `durum` alanı: kapsül yazılıyor; kuyruk özeti henüz geçerli değil.
pub const DURUM_YAZILIYOR: u32 = 1;

/// Kapsülün düz metin sabit başlığı.
///
/// Alanların tamamı kapsul dosyasında **düz metin** olarak durur; Argon2
/// parametreleri bilinçli olarak okunabilir tutulmuştur (rapor b10
/// "denetlenebilirlik" maddesi).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SabitBaslik {
    /// Bayrak bitleri; şu an yalnızca [`BAYRAK_DIZIN`] kullanılır.
    ///
    /// Yazma durumu burada değil `durum` alanındadır; nedeni için
    /// [`DURUM_TAMAM`] belgesine bakınız.
    pub bayraklar: u8,
    /// Parça başına düz metin uzunluğu (bayt).
    pub parca_boyutu: u32,
    /// Argon2 bellek maliyeti (KiB).
    pub argon2_bellek_kib: u32,
    /// Argon2 işlem turu sayısı.
    pub argon2_tur: u32,
    /// Argon2 paralellik (yol) sayısı.
    pub argon2_yol: u32,
    /// Manifest şifrelemesi için 96-bit nonce.
    pub manifest_nonce: [u8; NONCE_UZUNLUGU],
    /// Kapsüldeki girdi sayısı (dosya + dizin).
    pub girdi_sayisi: u32,
    /// Manifest için ayrılan toplam bayt (şifre metni + etiket).
    pub manifest_ayrilmis: u64,
    /// Payload için planlanan toplam bayt.
    pub payload_planlanan: u64,
    /// Payload'da fiilen yazılmış bayt; tamamlandığında `payload_planlanan`'a eşittir.
    pub yazilan_offset: u64,
    /// [`DURUM_TAMAM`] veya [`DURUM_YAZILIYOR`].
    pub durum: u32,
}

impl SabitBaslik {
    /// Başlığı 96 baytlık sabit uzunluklu diziye çevirir.
    pub fn kodla(&self) -> [u8; BASLIK_UZUNLUGU] {
        let mut bayt = [0u8; BASLIK_UZUNLUGU];
        bayt[0..4].copy_from_slice(&SIHRLI);
        bayt[4] = SURUM;
        bayt[5] = self.bayraklar;
        // 6..8 ve 60..64, 92..96 ayrılmış sıfırlar.
        bayt[8..12].copy_from_slice(&self.parca_boyutu.to_le_bytes());
        bayt[12..16].copy_from_slice(&self.argon2_bellek_kib.to_le_bytes());
        bayt[16..20].copy_from_slice(&self.argon2_tur.to_le_bytes());
        bayt[20..24].copy_from_slice(&self.argon2_yol.to_le_bytes());
        bayt[24..28].copy_from_slice(&(TUZ_UZUNLUGU as u32).to_le_bytes());
        // 28..44 tuz alanı; tuz kapsül başlığının parçası değildir (aşağıda).
        bayt[44..56].copy_from_slice(&self.manifest_nonce);
        bayt[56..60].copy_from_slice(&self.girdi_sayisi.to_le_bytes());
        bayt[64..72].copy_from_slice(&self.manifest_ayrilmis.to_le_bytes());
        bayt[72..80].copy_from_slice(&self.payload_planlanan.to_le_bytes());
        bayt[80..88].copy_from_slice(&self.yazilan_offset.to_le_bytes());
        bayt[88..92].copy_from_slice(&self.durum.to_le_bytes());
        bayt
    }

    /// 96 baytlık diziden başlığı ayrıştırır ve alan sınırlarını doğrular.
    pub fn coz(bayt: &[u8; BASLIK_UZUNLUGU]) -> Result<Self, Hata> {
        if bayt[0..4] != SIHRLI {
            return Err(Hata::BozukKapsul("sihirli sayi eslesmedi".into()));
        }
        if bayt[4] != SURUM {
            return Err(Hata::BozukKapsul(format!(
                "desteklenmeyen bicim surumu {}",
                bayt[4]
            )));
        }
        let parca_boyutu = oku_u32(bayt, 8);
        if !(EN_KUCUK_PARCA..=EN_BUYUK_PARCA).contains(&parca_boyutu) {
            return Err(Hata::BozukKapsul(format!(
                "parca boyutu {parca_boyutu} izinli aralik disinda"
            )));
        }
        let tuz_uzunlugu = oku_u32(bayt, 24);
        if tuz_uzunlugu as usize != TUZ_UZUNLUGU {
            return Err(Hata::BozukKapsul("tuz uzunlugu 16 olmali".into()));
        }
        let mut manifest_nonce = [0u8; NONCE_UZUNLUGU];
        manifest_nonce.copy_from_slice(&bayt[44..56]);
        Ok(SabitBaslik {
            bayraklar: bayt[5],
            parca_boyutu,
            argon2_bellek_kib: oku_u32(bayt, 12),
            argon2_tur: oku_u32(bayt, 16),
            argon2_yol: oku_u32(bayt, 20),
            manifest_nonce,
            girdi_sayisi: oku_u32(bayt, 56),
            manifest_ayrilmis: oku_u64(bayt, 64),
            payload_planlanan: oku_u64(bayt, 72),
            yazilan_offset: oku_u64(bayt, 80),
            durum: oku_u32(bayt, 88),
        })
    }

    /// Kapsül içinde tuzun durduğu bayt aralığını döndürür.
    ///
    /// Tuz düz metin başlığın bir parçasıdır: Argon2 girdisidir ve gizli değildir.
    pub fn tuz(bayt: &[u8; BASLIK_UZUNLUGU]) -> [u8; TUZ_UZUNLUGU] {
        let mut tuz = [0u8; TUZ_UZUNLUGU];
        tuz.copy_from_slice(&bayt[28..44]);
        tuz
    }

    /// Tuzu başlığın kodlanmış kopyasına yazar.
    ///
    /// Kodlanmış başlık döndürmek için gerekli olduğundan `kodla` yalnızca
    /// tuzsuz alanları doldurur; çağıran taraf `tuz_yaz` ile tamamlar.
    pub fn tuz_yaz(bayt: &mut [u8; BASLIK_UZUNLUGU], tuz: &[u8; TUZ_UZUNLUGU]) {
        bayt[28..44].copy_from_slice(tuz);
    }

    /// Başlık baytlarının `[0..64]` öneki (AES-GCM ek verisi).
    pub fn aad(bayt: &[u8; BASLIK_UZUNLUGU]) -> &[u8] {
        &bayt[0..AAD_UZUNLUGU]
    }

    /// Payload'un kapsül içinde başladığı ofset.
    pub fn payload_ofseti(&self) -> u64 {
        BASLIK_UZUNLUGU as u64 + self.manifest_ayrilmis
    }

    /// Kapsülün tamamının beklenen uzunluğu (kuyruk özeti dâhil).
    pub fn kapsul_uzunlugu(&self) -> u64 {
        self.payload_ofseti() + self.payload_planlanan + OZET_UZUNLUGU as u64
    }

    /// Kapsül bir klasör ağacı mı içeriyor?
    pub fn dizin_agaci(&self) -> bool {
        self.bayraklar & BAYRAK_DIZIN != 0
    }
}

/// Tek bir parçanın kapsül içindeki konumunu ve uzunluğunu tanımlar.
///
/// Ofsetler payload alanının başına görelidir; böylece manifest şifreli
/// bölümün uzunluğu değişse bile parça adresleri değişmez.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParcaKonumu {
    /// Parçanın rastgele 96-bit nonce'u.
    pub nonce: [u8; NONCE_UZUNLUGU],
    /// Parça gövdesinin payload alanına göre ofseti.
    pub ofset: u64,
    /// Parçanın şifre metni uzunluğu (etiket bu sayıya **dahil değildir**).
    pub sifre_uzunlugu: u32,
}

impl ParcaKonumu {
    /// Parçanın kapsülde kapladığı toplam bayt (nonce + uzunluk + metin + etiket).
    pub fn toplam_bayt(&self) -> u64 {
        parca_kayit_uzunlugu(self.sifre_uzunlugu)
    }
}

/// Bir parça kaydının kapsülde kapladığı sabit + şifre metni baytı.
pub fn parca_kayit_uzunlugu(sifre_uzunlugu: u32) -> u64 {
    (NONCE_UZUNLUGU + 4 + sifre_uzunlugu as usize + ETIKET_UZUNLUGU) as u64
}

fn oku_u32(bayt: &[u8; BASLIK_UZUNLUGU], ofset: usize) -> u32 {
    u32::from_le_bytes([
        bayt[ofset],
        bayt[ofset + 1],
        bayt[ofset + 2],
        bayt[ofset + 3],
    ])
}

fn oku_u64(bayt: &[u8; BASLIK_UZUNLUGU], ofset: usize) -> u64 {
    let mut tampon = [0u8; 8];
    tampon.copy_from_slice(&bayt[ofset..ofset + 8]);
    u64::from_le_bytes(tampon)
}

#[cfg(test)]
// `unwrap`/`expect` testlerde kabul edilir (WORKER_CONTRACT §4.2).
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn ornek() -> SabitBaslik {
        SabitBaslik {
            bayraklar: BAYRAK_DIZIN,
            parca_boyutu: VARSAYILAN_PARCA,
            argon2_bellek_kib: 65_536,
            argon2_tur: 3,
            argon2_yol: 4,
            manifest_nonce: [0x11; NONCE_UZUNLUGU],
            girdi_sayisi: 7,
            manifest_ayrilmis: 4_096,
            payload_planlanan: 1_048_576,
            yazilan_offset: 1_048_576,
            durum: DURUM_TAMAM,
        }
    }

    #[test]
    fn baslik_kodla_coz_gidis_donus_basar() {
        let baslik = ornek();
        let kodlu = baslik.kodla();
        assert_eq!(kodlu.len(), BASLIK_UZUNLUGU);
        assert_eq!(SabitBaslik::coz(&kodlu).unwrap(), baslik);
    }

    #[test]
    fn baslik_kodlamasi_kucuk_endianli_ve_ayri_lik_alanlari_sifirdir() {
        let kodlu = ornek().kodla();
        assert_eq!(&kodlu[0..4], b"SBX1");
        assert_eq!(kodlu[4], SURUM);
        assert_eq!(&kodlu[6..8], &[0, 0], "ayri alan sifir olmali");
        assert_eq!(&kodlu[60..64], &[0, 0, 0, 0], "AAD sonu ayri alan sifir");
        assert_eq!(&kodlu[92..96], &[0, 0, 0, 0]);
        // m_cost = 65536 = 0x00010000 LE
        assert_eq!(&kodlu[12..16], &[0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn bozuk_sihirli_sayi_reddedilir() {
        let mut kodlu = ornek().kodla();
        kodlu[0] = b'X';
        assert!(matches!(
            SabitBaslik::coz(&kodlu),
            Err(Hata::BozukKapsul(_))
        ));
    }

    #[test]
    fn desteklenmeyen_surum_reddedilir() {
        let mut kodlu = ornek().kodla();
        kodlu[4] = 9;
        assert!(SabitBaslik::coz(&kodlu).is_err());
    }

    #[test]
    fn aralik_disi_parca_boyutu_reddedilir() {
        let mut kodlu = ornek().kodla();
        kodlu[8..12].copy_from_slice(&1024u32.to_le_bytes());
        assert!(SabitBaslik::coz(&kodlu).is_err());
    }

    #[test]
    fn aad_yuzde_alti_dort_bayt_ile_sinirlidir() {
        let kodlu = ornek().kodla();
        assert_eq!(SabitBaslik::aad(&kodlu).len(), AAD_UZUNLUGU);
        assert_eq!(SabitBaslik::aad(&kodlu), &kodlu[0..64]);
        // Degismeyen bolum: durum alani 88'de, AAD disinda.
        assert!(SabitBaslik::aad(&kodlu).get(88).is_none());
    }

    #[test]
    fn tuz_kodlanip_geri_okunur() {
        let mut kodlu = ornek().kodla();
        let tuz: [u8; TUZ_UZUNLUGU] = [0xA5; TUZ_UZUNLUGU];
        SabitBaslik::tuz_yaz(&mut kodlu, &tuz);
        assert_eq!(SabitBaslik::tuz(&kodlu), tuz);
    }

    #[test]
    fn uzunluk_hesaplari_tutarli() {
        let baslik = ornek();
        assert_eq!(baslik.payload_ofseti(), 96 + 4_096);
        assert_eq!(baslik.kapsul_uzunlugu(), 96 + 4_096 + 1_048_576 + 64);
        assert!(baslik.dizin_agaci());
    }

    #[test]
    fn parca_kayit_uzunlugu_sabit_yuk_ekler() {
        // nonce(12) + uzunluk(4) + etiket(16) = 32 bayt sabit yük
        assert_eq!(parca_kayit_uzunlugu(0), 32);
        assert_eq!(parca_kayit_uzunlugu(1000), 1032);
        let parca = ParcaKonumu {
            nonce: [0; NONCE_UZUNLUGU],
            ofset: 0,
            sifre_uzunlugu: 1000,
        };
        assert_eq!(parca.toplam_bayt(), 1032);
    }
}
