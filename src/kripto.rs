//! Kriptografik çekirdek: Argon2id anahtar türetme, HKDF alt anahtar türetme,
//! AES-256-GCM parça şifreleme/çözme ve `getrandom` ile nonce üretimi.
//!
//! Modülün sorumluluğu "bayt dizisini güvenli biçimde dönüştürmektir"; dosya
//! sistemi, yol ve biçim bilgisi burada yaşamaz.
//!
//! Tasarım kuralları (MANIFEST kart 17):
//! - AES-256-GCM ve Argon2id **el yazımı değildir**; RustCrypto crate'leriyle
//!   sağlanır (karar D-008).
//! - Nonce **asla sayaç değildir**; her parça için işletim sistemi
//!   kriptografik rastgeleliğinden 96-bit üretilir (rapor b10, "nonce yeniden
//!   kullanımı" satırı).
//! - Etiket doğrulaması başarısız olduğan çözme, düz metni çağırana **hiç**
//!   teslim etmez; tampon `zeroize` ile temizlenir.
//! - Anahtar malzemesi `zeroize::Zeroizing` içinde taşınır ve düşünce sonunda
//!   sıfırlanır.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::hata::Hata;
use crate::kapsul::{EN_AZ_BELLEK_KIB, EN_FAZLA_BELLEK_KIB, ETIKET_UZUNLUGU, NONCE_UZUNLUGU};

/// AES-256 anahtar uzunluğu (bayt).
pub const ANAHTAR_UZUNLUGU: usize = 32;

/// Argon2id türetme parametreleri.
///
/// Varsayılanlar rapor b10'daki öneriyle aynıdır: 64 MiB bellek, 3 tur,
/// 4 yol. Değerler kapsül başlığında **açıkça saklanır**; bu, kaba kuvvet
/// saldırısının pahalı olmasını sağlarken denetlenebilirliği korur.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Ayar {
    /// Bellek maliyeti (KiB).
    pub bellek_kib: u32,
    /// İşlem turu sayısı.
    pub tur: u32,
    /// Paralellik (yol) sayısı.
    pub yol: u32,
}

impl Default for Argon2Ayar {
    fn default() -> Self {
        Argon2Ayar {
            bellek_kib: 65_536,
            tur: 3,
            yol: 4,
        }
    }
}

impl Argon2Ayar {
    /// Rapor b10'da tanımlanan izinli aralıkları doğrular.
    pub fn dogrula(&self) -> Result<(), Hata> {
        if !(EN_AZ_BELLEK_KIB..=EN_FAZLA_BELLEK_KIB).contains(&self.bellek_kib) {
            return Err(Hata::BozukArguman(format!(
                "Argon2 bellek maliyeti {} KiB; izinli aralik {}..{}",
                self.bellek_kib, EN_AZ_BELLEK_KIB, EN_FAZLA_BELLEK_KIB
            )));
        }
        if !(1..=10).contains(&self.tur) {
            return Err(Hata::BozukArguman(format!(
                "Argon2 tur sayisi {}; izinli aralik 1..10",
                self.tur
            )));
        }
        if !(1..=16).contains(&self.yol) {
            return Err(Hata::BozukArguman(format!(
                "Argon2 yol sayisi {}; izinli aralik 1..16",
                self.yol
            )));
        }
        // Argon2 her yola en az 8 KiB ayırmak zorundadır.
        if u64::from(self.bellek_kib) < 8 * u64::from(self.yol) {
            return Err(Hata::BozukArguman(
                "Argon2 bellek maliyeti yol sayisindan kucuk olamaz".into(),
            ));
        }
        Ok(())
    }
}

/// HKDF bilgi (info) etiketleri. Amaç ayrımı, alt anahtarların birbirinden
/// bağımsız türetilmesini garanti eder.
pub const AMAÇ_ANA: &[u8] = b"sealedbox/v1/ana-anahtar";
/// Dosya alt anahtarı için HKDF bilgi öneki.
pub const AMAÇ_DOSYA: &[u8] = b"sealedbox/v1/dosya-alt-anahtar";

/// İşletim sistemi kriptografik rastgeleliğinden `uzunluk` bayt üretir.
pub fn rastgele_bayt(uzunluk: usize) -> Result<Zeroizing<Vec<u8>>, Hata> {
    let mut tampon = vec![0u8; uzunluk];
    getrandom::fill(&mut tampon).map_err(|hata| {
        Hata::Kriptografik(format!("isletim sistemi rastgeleligi alinamadi: {hata}"))
    })?;
    Ok(Zeroizing::new(tampon))
}

/// 96-bit rastgele parça nonce'u üretir.
///
/// Bu fonksiyon bilinçli olarak bir sayaç içermez: GCM'de nonce tekrarı
/// kriptografik çökmedir ve rastgelelik tek başına güvenli kabul edilir
/// (rapor b07/b10).
pub fn nonce_uret() -> Result<[u8; NONCE_UZUNLUGU], Hata> {
    let bayt = rastgele_bayt(NONCE_UZUNLUGU)?;
    let mut nonce = [0u8; NONCE_UZUNLUGU];
    nonce.copy_from_slice(&bayt[..NONCE_UZUNLUGU]);
    Ok(nonce)
}

/// Paroladan Argon2id ile 32 baytlık ana malzeme türetir.
///
/// Sonuç `Zeroizing` içinde döner; çağıran bunı diske yazmaz ve düşünce
/// sonunda bellek sıfırlanır.
pub fn ana_malzeme_turet(
    parola: &[u8],
    tuz: &[u8; 16],
    ayar: &Argon2Ayar,
) -> Result<Zeroizing<[u8; ANAHTAR_UZUNLUGU]>, Hata> {
    ayar.dogrula()?;
    let parametreler = argon2::Params::new(ayar.bellek_kib, ayar.tur, ayar.yol, None)
        .map_err(|hata| Hata::Kriptografik(format!("Argon2 parametreleri gecersiz: {hata}")))?;
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        parametreler,
    );
    let mut malzeme = Zeroizing::new([0u8; ANAHTAR_UZUNLUGU]);
    argon2
        .hash_password_into(parola, tuz, malzeme.as_mut())
        .map_err(|hata| Hata::Kriptografik(format!("Argon2 turetme basarisiz: {hata}")))?;
    Ok(malzeme)
}

/// Ana malzemeden HKDF-SHA256 ile belirtilen amaca ait alt anahtar türetir.
///
/// `sira`, dosya alt anahtarında dosya indeksini temsil eder; iki farklı dosya
/// asla aynı anahtarı paylaşmaz. Böylece iki farklı dosyada rastlantısal bir
/// nonce tekrarı olsa bile şifre çökmez.
pub fn alt_anahtar(
    ana_malzeme: &[u8; ANAHTAR_UZUNLUGU],
    tuz: &[u8; 16],
    amac: &[u8],
    sira: u64,
) -> Result<Zeroizing<[u8; ANAHTAR_UZUNLUGU]>, Hata> {
    let mut bilgi = Vec::with_capacity(amac.len() + 8);
    bilgi.extend_from_slice(amac);
    bilgi.extend_from_slice(&sira.to_be_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(tuz), ana_malzeme);
    let mut anahtar = Zeroizing::new([0u8; ANAHTAR_UZUNLUGU]);
    hkdf.expand(&bilgi, anahtar.as_mut()).map_err(|hata| {
        Hata::Kriptografik(format!("HKDF alt anahtar turetme basarisiz: {hata}"))
    })?;
    Ok(anahtar)
}

/// Bir parçanın konumunu bağlayan 16 baytlık ek veri (AAD).
///
/// Parçayı kapüldeki (dosya sırası, parça sırası) çiftine bağlar. Böylece bir
/// parçanın yer değiştirilmesi veya kesilmesi, doğrudan etik doğrulamasında
/// yakalanır; kapsül genelinde bir parçanın silinip yerine başka parça konması
/// mümkün değildir.
pub fn parca_ek_verisi(dosya_sirasi: u64, parca_sirasi: u64) -> [u8; 16] {
    let mut ek = [0u8; 16];
    ek[..8].copy_from_slice(&dosya_sirasi.to_be_bytes());
    ek[8..].copy_from_slice(&parca_sirasi.to_be_bytes());
    ek
}

fn motor(anahtar: &[u8; ANAHTAR_UZUNLUGU]) -> Result<Aes256Gcm, Hata> {
    Aes256Gcm::new_from_slice(anahtar)
        .map_err(|hata| Hata::Kriptografik(format!("AES-256 anahtari yuklenemedi: {hata}")))
}

/// Parçayı yerinde şifreler ve 16 baytlık Poly1305 etiketini döndürür.
///
/// `veri` üzerinde çalışılır; şifreli çıktı aynı tamponda kalır (GCM bir
// akış şifresidir, şifre metni düz metinle aynı uzunluktadır). Girdi düz metin
/// olduğu için, çağıran tamponu iş bitince `zeroize` ile temizler.
pub fn parca_sifrele(
    anahtar: &[u8; ANAHTAR_UZUNLUGU],
    nonce: &[u8; NONCE_UZUNLUGU],
    ek_veri: &[u8],
    veri: &mut [u8],
) -> Result<[u8; ETIKET_UZUNLUGU], Hata> {
    let sifre = motor(anahtar)?;
    let etiket = sifre
        .encrypt_in_place_detached(Nonce::from_slice(nonce), ek_veri, veri)
        .map_err(|hata| Hata::Kriptografik(format!("parca sifreleme basarisiz: {hata}")))?;
    let mut sonuc = [0u8; ETIKET_UZUNLUGU];
    sonuc.copy_from_slice(&etiket[..]);
    Ok(sonuc)
}

/// Parçayı yerinde çözer; etiket doğrulanamazsa düz metin **sıfırlanarak**
/// hata döner.
///
/// `aes-gcm` etiketi doğruladıktan *sonra* düz metni teslim edebilir; bu yüzden
/// hata yolunda tamponu `zeroize` ile temizliyoruz. Çözülen düz metin
/// diske/doğrulayıcıya ancak bu fonksiyon başarıyla döndükten sonra yazılır.
pub fn parca_coz(
    anahtar: &[u8; ANAHTAR_UZUNLUGU],
    nonce: &[u8; NONCE_UZUNLUGU],
    ek_veri: &[u8],
    veri: &mut [u8],
    etiket: &[u8; ETIKET_UZUNLUGU],
) -> Result<(), Hata> {
    let sifre = motor(anahtar)?;
    let sonuc = sifre.decrypt_in_place_detached(
        Nonce::from_slice(nonce),
        ek_veri,
        veri,
        Tag::from_slice(etiket),
    );
    match sonuc {
        Ok(()) => Ok(()),
        Err(_) => {
            // Duz metin uretilmis olabilir; cikis yazilmadan once temizlenir.
            veri.fill(0);
            Err(Hata::BozukKapsul("parca etigi dogrulanmadi".into()))
        }
    }
}

/// Manifest'i (kapsül dizin kaydını) şifreler ve 16 baytlık etiketini döndürür.
///
/// Manifest, ana anahtarla ve kapsül başlığının değişmez `[0..64]` öneğiyle
/// şifrelenir. Böylece parça boyutu, Argon2 parametreleri ve tuz, manifest'i
/// çözmeden değiştirilemez.
pub fn manifest_sifrele(
    anahtar: &[u8; ANAHTAR_UZUNLUGU],
    nonce: &[u8; NONCE_UZUNLUGU],
    ek_veri: &[u8],
    veri: &mut [u8],
) -> Result<[u8; ETIKET_UZUNLUGU], Hata> {
    parca_sifrele(anahtar, nonce, ek_veri, veri)
}

/// Manifest'i çözer; etiket doğrulanamazsa hata döner.
///
/// **Güvenlik notu:** bu fonksiyonun hata mesajı "parola yanlış veya kapsul
/// bütünlüğü bozuk" biçiminde birleşiktir. Yanlış parola ile bozulmuş
/// manifest arasında ayrım yapmak kriptografik olarak mümkün değildir ve
/// yapılmamalıdır.
pub fn manifest_coz(
    anahtar: &[u8; ANAHTAR_UZUNLUGU],
    nonce: &[u8; NONCE_UZUNLUGU],
    ek_veri: &[u8],
    veri: &mut [u8],
    etiket: &[u8; ETIKET_UZUNLUGU],
) -> Result<(), Hata> {
    parca_coz(anahtar, nonce, ek_veri, veri, etiket)
}

/// Kapsül düzeyinde SHA-512 bütünlük özeti üretir.
///
/// Parça etikleri gövdeyi korur; bu özet ise manifest bloğu, başlık ve
/// kapsül sonundaki ek baytlar gibi parça kapsamı dışındaki hataları yakalar
/// (rapor b10 "Kapsül bütünlüğü" satırı).
pub fn kapsul_ozeti(
    okuyucu: &mut dyn std::io::Read,
    kapsul_uzunlugu: u64,
) -> Result<[u8; 64], Hata> {
    use sha2::Digest;
    let mut hasher = sha2::Sha512::new();
    let mut tampon = vec![0u8; 1 << 20];
    let mut kalan = kapsul_uzunlugu;
    while kalan > 0 {
        let istenen = std::cmp::min(kalan, tampon.len() as u64) as usize;
        let okunan = okuyucu.read(&mut tampon[..istenen]).map_err(Hata::Io)?;
        if okunan == 0 {
            return Err(Hata::BozukKapsul(
                "kuyruk ozeti icin beklenenden az bayt".into(),
            ));
        }
        hasher.update(&tampon[..okunan]);
        kalan -= okunan as u64;
    }
    let sonuc = hasher.finalize();
    let mut ozet = [0u8; 64];
    ozet.copy_from_slice(&sonuc);
    Ok(ozet)
}

/// İki özeti sabit zamanlı karşılaştırır.
///
/// `==` operatörü kısa devre yaptığı ve zamanlama sızıntısı yaratabileceği
/// için kullanılmaz (MANIFEST kart 17, risk listesi "sabit zamanlılık" maddesi).
pub fn ozitler_esit(sol: &[u8; 64], sag: &[u8; 64]) -> bool {
    let mut fark = 0u8;
    for (a, b) in sol.iter().zip(sag.iter()) {
        fark |= a ^ b;
    }
    fark == 0
}

#[cfg(test)]
// `unwrap`/`expect` testlerde kabul edilir (WORKER_CONTRACT §4.2).
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Test vektörlerindeki AES-256 anahtarı: 32 bayt sıfır.
    const KAT_ANAHTAR: [u8; ANAHTAR_UZUNLUGU] = [0u8; ANAHTAR_UZUNLUGU];
    /// Test vektörlerindeki 96-bit nonce: 12 bayt sıfır.
    const KAT_NONCE: [u8; NONCE_UZUNLUGU] = [0u8; NONCE_UZUNLUGU];

    #[test]
    fn nist_sp_800_38d_katsayim_13_bos_metin() {
        // NIST SP 800-38D, "GCM Test Vectors", AES-256, Test Case 13.
        // K = 0^256, IV = 0^96, P = "", C = "", T = 530f8afbc74536b9a963b4f1c4cb738b
        let etiket = parca_sifrele(&KAT_ANAHTAR, &KAT_NONCE, &[], &mut []).unwrap();
        assert_eq!(
            etiket.to_vec(),
            vec![
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b
            ]
        );
    }

    #[test]
    fn nist_sp_800_38d_katsayim_14_tek_blok() {
        // Test Case 14: P = 0^128, C = cea7403d4d606b6e074ec5d3baf39d18
        let mut veri = vec![0u8; 16];
        let etiket = parca_sifrele(&KAT_ANAHTAR, &KAT_NONCE, &[], &mut veri).unwrap();
        assert_eq!(
            veri.to_vec(),
            vec![
                0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
                0x9d, 0x18
            ]
        );
        assert_eq!(
            etiket.to_vec(),
            vec![
                0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
                0xb9, 0x19
            ]
        );
    }

    #[test]
    fn nist_sp_800_38d_cok_blok_akis_ozelligi_yayilir() {
        // NIST SP 800-38D Test Case 14 (P = 0^128) referans alinir.
        // GCM bir akis şifresidir: ayni anahtar/nonce ile daha uzun duz metnin
        // sifre metni, kisa metnin sifre metniyle **onek** olarak baslar. Bu
        // denetim yayimlanmis bir deger uzerinden yapildigi icin "kendi
        // ciktimizi kendimize kiyaslamak" dongusune girmez.
        let mut kisa = vec![0u8; 16];
        let kisa_etiket = parca_sifrele(&KAT_ANAHTAR, &KAT_NONCE, &[], &mut kisa).unwrap();
        let mut uzun = vec![0u8; 64];
        let _ = parca_sifrele(&KAT_ANAHTAR, &KAT_NONCE, &[], &mut uzun).unwrap();
        assert_eq!(&uzun[..16], &kisa[..], "CTR akisi oneki korumali");
        assert_eq!(
            kisa,
            vec![
                0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
                0x9d, 0x18
            ]
        );
        assert_eq!(
            kisa_etiket.to_vec(),
            vec![
                0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
                0xb9, 0x19
            ]
        );
    }

    #[test]
    fn etiket_uzunlugu_kapsar() {
        // Etiket yalnizca sifre metnini degil, uzunlugu da kapsar: ayni onek,
        // farkli boyut -> farkli etiket.
        let mut onalti = vec![0u8; 16];
        let mut otuziki = vec![0u8; 32];
        let bir = parca_sifrele(&KAT_ANAHTAR, &KAT_NONCE, &[], &mut onalti).unwrap();
        let iki = parca_sifrele(&KAT_ANAHTAR, &KAT_NONCE, &[], &mut otuziki).unwrap();
        assert_ne!(bir, iki);
        assert_eq!(&onalti[..], &otuziki[..16], "on ek yine ayni");
    }

    #[test]
    fn ayni_duz_metin_iki_kez_farkli_sifre_meti_verir() {
        // Nonce rastgele uretildigi icin ayni duz metin iki karsilistirmada
        // farkli sifre metni vermelidir; bu, nonce'in gercekten her parcada
        // yenilendigini kanitlar.
        let anahtar = Zeroizing::new([5u8; ANAHTAR_UZUNLUGU]);
        let mut bir = b"ayni duz metin".to_vec();
        let mut iki = b"ayni duz metin".to_vec();
        let _ = parca_sifrele(&anahtar, &nonce_uret().unwrap(), b"a", &mut bir).unwrap();
        let _ = parca_sifrele(&anahtar, &nonce_uret().unwrap(), b"a", &mut iki).unwrap();
        assert_ne!(bir, iki);
    }

    #[test]
    fn rfc_9106_argon2id_test_vektoru() {
        // RFC 9106, Bölüm 5 "Test Vectors" — Argon2id v=0x13.
        // Memory: 32 KiB, Iterations: 3, Parallelism: 4, Tag: 32 bayt
        // P[32] = 0x01*32, S[16] = 0x02*16, K[8] = 0x03*8, X[12] = 0x04*12
        let parametreler = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[0x04; 12]).unwrap())
            .build()
            .unwrap();
        let argon2 = argon2::Argon2::new_with_secret(
            &[0x03; 8],
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            parametreler,
        )
        .unwrap();
        let mut sonuc = [0u8; 32];
        argon2
            .hash_password_into(&[0x01; 32], &[0x02; 16], &mut sonuc)
            .unwrap();
        let beklenen: [u8; 32] = [
            0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b,
            0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9,
            0x6b, 0x01, 0xe6, 0x59,
        ];
        assert_eq!(sonuc, beklenen);
    }

    #[test]
    fn parca_gidis_donus_basar() {
        let anahtar = Zeroizing::new([7u8; ANAHTAR_UZUNLUGU]);
        let mut veri = b"muhrur kasa akis testi".to_vec();
        let duz = veri.clone();
        let etiket = parca_sifrele(&anahtar, &KAT_NONCE, b"aad", &mut veri).unwrap();
        assert_ne!(veri, duz, "sifreli metin duz metinden farkli olmali");
        parca_coz(&anahtar, &KAT_NONCE, b"aad", &mut veri, &etiket).unwrap();
        assert_eq!(veri, duz);
    }

    #[test]
    fn bozuk_etik_dogrulamayi_basarisiz_kilar_ve_tamponu_sifirlar() {
        let anahtar = Zeroizing::new([7u8; ANAHTAR_UZUNLUGU]);
        let mut veri = b"gizli icerik".to_vec();
        let etiket = parca_sifrele(&anahtar, &KAT_NONCE, b"aad", &mut veri).unwrap();
        let mut bozuk = etiket;
        bozuk[0] ^= 0x01;
        let sonuc = parca_coz(&anahtar, &KAT_NONCE, b"aad", &mut veri, &bozuk);
        assert!(sonuc.is_err());
        assert!(
            veri.iter().all(|bayt| *bayt == 0),
            "etiket dogrulanmadan duz metin cikisi temizlenmeli"
        );
    }

    #[test]
    fn yanlis_ek_veri_dogrulamayi_basarisiz_kilar() {
        let anahtar = Zeroizing::new([7u8; ANAHTAR_UZUNLUGU]);
        let mut veri = b"konum baglayici".to_vec();
        let etiket = parca_sifrele(&anahtar, &KAT_NONCE, b"birinci", &mut veri).unwrap();
        assert!(parca_coz(&anahtar, &KAT_NONCE, b"ikinci", &mut veri, &etiket).is_err());
    }

    #[test]
    fn alt_anahtarlar_sira_ve_amaca_gore_ayrilir() {
        let ana_malzeme = Zeroizing::new([1u8; ANAHTAR_UZUNLUGU]);
        let tuz = [9u8; 16];
        let bir = alt_anahtar(&ana_malzeme, &tuz, AMAÇ_DOSYA, 0).unwrap();
        let iki = alt_anahtar(&ana_malzeme, &tuz, AMAÇ_DOSYA, 1).unwrap();
        let ana = alt_anahtar(&ana_malzeme, &tuz, AMAÇ_ANA, 0).unwrap();
        assert_ne!(*bir, *iki, "farkli siralar farkli alt anahtar uretmeli");
        assert_ne!(*bir, *ana, "farkli amaclar farkli alt anahtar uretmeli");
    }

    #[test]
    fn nonce_uretimi_rastgele_ve_tekildir() {
        let mut gorulen = std::collections::HashSet::new();
        for _ in 0..256 {
            let nonce = nonce_uret().unwrap();
            assert_eq!(nonce.len(), NONCE_UZUNLUGU);
            assert!(gorulen.insert(nonce), "256 rastgele nonce tekrar etmemeli");
        }
    }

    #[test]
    fn zeroize_sonrasi_tampon_sifirdir() {
        let mut anahtar = Zeroizing::new([0xABu8; ANAHTAR_UZUNLUGU]);
        use zeroize::Zeroize;
        anahtar.zeroize();
        assert!(anahtar.iter().all(|bayt| *bayt == 0));
    }

    #[test]
    fn parca_ek_verisi_konumu_baglar() {
        assert_ne!(
            parca_ek_verisi(0, 0),
            parca_ek_verisi(0, 1),
            "parca sirasi ek veriye yansimali"
        );
        assert_ne!(parca_ek_verisi(0, 5), parca_ek_verisi(1, 5));
    }

    #[test]
    fn ozit_karsilastirmasi_sabit_zamanli_ve_dogrudur() {
        let bir = [0u8; 64];
        let mut iki = [0u8; 64];
        assert!(ozitler_esit(&bir, &iki));
        iki[63] = 1;
        assert!(!ozitler_esit(&bir, &iki));
    }

    #[test]
    fn argon2_ayari_izinli_ariligi_uygular() {
        let varsayilan = Argon2Ayar::default();
        assert!(varsayilan.dogrula().is_ok());
        let kucuk = Argon2Ayar {
            bellek_kib: 8 * 1024,
            tur: 3,
            yol: 4,
        };
        assert!(kucuk.dogrula().is_err(), "16 MiB alti reddedilmeli");
        let cok_yol = Argon2Ayar {
            bellek_kib: 65_536,
            tur: 3,
            yol: 0,
        };
        assert!(cok_yol.dogrula().is_err());
    }

    #[test]
    fn ana_malzeme_parolaya_duyarlidir() {
        let tuz = [3u8; 16];
        let ayar = Argon2Ayar {
            bellek_kib: 16_384,
            tur: 1,
            yol: 1,
        };
        let bir = ana_malzeme_turet(b"dogru parola", &tuz, &ayar).unwrap();
        let iki = ana_malzeme_turet(b"yanlis parola", &tuz, &ayar).unwrap();
        assert_ne!(*bir, *iki);
        let baska_tuz = [4u8; 16];
        let uc = ana_malzeme_turet(b"dogru parola", &baska_tuz, &ayar).unwrap();
        assert_ne!(*bir, *uc, "tuz degisimi ciktiyi degistirmeli");
    }
}
