//! Kapsül doğrulama: içeriği çözmeden tüm parça etiketlerini sınamak.
//!
//! Bu modül, çözme (`akis::ac`) ile doğrulama arasındaki tek farkı taşır:
//! düz metin **hiçbir yere yazılmaz**, yalnızca etik karşılaştırması için
//! kısa ömürlü bir tampona alınır ve hemen sıfırlanır. Böylece bir arşivin
//! "hâlâ sağlam mı" sorusu, içeriğe erişmeden cevaplanır (rapor b03,
//! "kapsül düzeyinde sağlama değeri" kabul kriteri).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;
use zeroize::Zeroizing;

use crate::akis::{kapsul_ac, manifest_oku_dosyadan, AcSecenekleri};
use crate::dizin::Tur;
use crate::hata::Hata;
use crate::kapsul::{ETIKET_UZUNLUGU, NONCE_UZUNLUGU};
use crate::kripto::{alt_anahtar, parca_coz, parca_ek_verisi, AMAÇ_DOSYA};

/// Doğrulama sonucunu özetleyen yapı.
#[derive(Clone, Debug)]
pub struct DogrulamaRaporu {
    /// Doğrulanan kapsülün yolu.
    pub kapsul: String,
    /// Etiketi doğrulanan parça sayısı.
    pub dogrulanan_parca: u64,
    /// Doğrulanan düz metin baytı.
    pub dogrulanan_bayt: u64,
    /// Kapsüldeki dosya sayısı.
    pub dosya_sayisi: u64,
    /// Kapsül düzeyi SHA-512 kuyruk özeti doğrulandı mı.
    pub kuyruk_ozeti_dogrulandi: bool,
    /// Genel sonuç: `"tamam"` veya hata mesajı.
    pub sonuc: String,
    /// Geçen süre (milisaniye).
    pub sure_ms: u128,
}

/// Kapsülü açar ve **çözmeden** tüm parçaların etiketlerini doğrular.
///
/// Yanlış parola, bozuk kapsül veya tek bayt değişmiş bir parça burada hata
/// döndürür; çıktı diski hiç dokunulmadan bırakılır.
pub fn dogrula(kapsul_yolu: &Path, parola: &[u8]) -> Result<DogrulamaRaporu, Hata> {
    let baslangic = Instant::now();
    // Kapsul duzeyi ozet, parca etikleri **sonra** denetlenir: ozet butunluk
    // icin gereklidir ama hatanin yerini bildirmez. Siralama sayesinde
    // kullaniciya "hangi parca bozuk" bilgisi ulasir.
    let secenek = AcSecenekleri {
        kuyruk_ozetini_dogrula: false,
        ..AcSecenekleri::default()
    };
    let (baslik, ana_anahtar, tuz) = kapsul_ac(kapsul_yolu, parola, &secenek)?;
    if baslik.durum != crate::kapsul::DURUM_TAMAM {
        return Err(Hata::BozukKapsul("kapsul yazilmamis".into()));
    }
    let manifest = manifest_oku_dosyadan(kapsul_yolu, &baslik, &ana_anahtar)?;
    let mut dosya = File::open(kapsul_yolu)?;
    let payload_baslangic = baslik.payload_ofseti();
    let mut dogrulanan_parca = 0u64;
    let mut dogrulanan_bayt = 0u64;
    let dosya_sayisi = manifest
        .girdiler
        .iter()
        .filter(|g| g.tur == Tur::Dosya)
        .count() as u64;

    for (sira, giris) in manifest.girdiler.iter().enumerate() {
        if giris.tur != Tur::Dosya {
            continue;
        }
        let alt = alt_anahtar(&ana_anahtar, &tuz, AMAÇ_DOSYA, sira as u64)?;
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
            dogrulanan_bayt += sifre.len() as u64;
            dogrulanan_parca += 1;
        }
    }

    // Parcalar saglam; simdi kapsul duzeyi butunluk ozeti.
    crate::akis::kuyruk_ozetini_dogrula(kapsul_yolu, &baslik)?;

    Ok(DogrulamaRaporu {
        kapsul: kapsul_yolu.display().to_string(),
        dogrulanan_parca,
        dogrulanan_bayt,
        dosya_sayisi,
        kuyruk_ozeti_dogrulandi: true,
        sonuc: "tamam".to_string(),
        sure_ms: baslangic.elapsed().as_millis(),
    })
}
