//! Bozulma, saldırı ve hata senaryoları.
//!
//! Kapsanan senaryolar: yanlış parola, bit çevirme (şifre metni / etiket /
//! başlık / kuyruk özeti), parça sırası karıştırma, kesik dosya, sona eklenen
//! bayt, bozuk biçim sürümü, üzerine yazma reddi, iptal ve geçici dosya temizliği.

mod yardimci;

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sealedbox::akis::{ac, muhurle, AcSecenekleri, MuhurSecenekleri};
use sealedbox::Hata;
use yardimci::{hizli_argon2, veri, GeciciDizin};

const PAROLA: &[u8] = b"dogru test parcasi 2026";
const YANLIS: &[u8] = b"yanlis test parcasi!!";
const KUCUK_PARCA: u32 = 512 * 1024;

fn hizli() -> MuhurSecenekleri {
    MuhurSecenekleri {
        parca_boyutu: KUCUK_PARCA,
        argon2: hizli_argon2(),
        ..MuhurSecenekleri::default()
    }
}

/// Sabit başlık (96) + kuyruk özeti (64) uzunlukları.
const BASLIK: u64 = 96;
const KUYRUK: u64 = 64;

/// Kapsülü okur, bir bayt çevirir, geri yazar.
fn bayt_cevir(yol: &std::path::Path, ofset: u64) {
    let mut bayt = fs::read(yol).unwrap();
    let konum = ofset as usize;
    assert!(konum < bayt.len(), "ofset kapsul disinda");
    bayt[konum] ^= 0x01;
    fs::write(yol, &bayt).unwrap();
}

/// Tek parçalı, 1000 baytlık bir kapsül üretir ve payload başlangıcını hesaplar.
fn tek_parcali_kapsul(gecici: &GeciciDizin, ad: &str, boyut: usize) -> std::path::PathBuf {
    let kaynak = gecici.yaz(ad, &veri(boyut, 17));
    let kapsul = gecici.birles(&format!("{ad}.sbx"));
    muhurle(&kaynak, &kapsul, PAROLA, &hizli()).unwrap();
    kapsul
}

/// Tek parçalı kapsülün payload alanının başlangıç ofsetini döndürür.
///
/// `payload_start = toplam - 64 - (32 + boyut)`: kuyruk özeti (64) ve tek
/// parçanın kayıt yükü (nonce 12 + uzunluk 4 + etiket 16 = 32) çıkarılır.
/// Sabit başlık (96) **çıkarılmaz**, çünkü aranan ofset tam olarak
/// `96 + manifest` konumudur.
fn payload_baslangici(kapsul: &std::path::Path, boyut: usize) -> u64 {
    let toplam = fs::metadata(kapsul).unwrap().len();
    toplam - KUYRUK - 32 - boyut as u64
}

/// Cok parcali kapsulde payload baslangici: `toplam - 64 - payload`.
///
/// `payload`, tum parca kayitlarinin (nonce 12 + uzunluk 4 + etiket 16 = 32 bayt
/// sabit yük) ve sifre metinlerinin toplamidir.
fn payload_baslangici_cok_parca(kapsul: &std::path::Path, parca: u64, boyut: u64) -> u64 {
    let toplam = fs::metadata(kapsul).unwrap().len();
    toplam - KUYRUK - parca * 32 - boyut
}

#[test]
fn yanlis_parola_kapsulu_acmaz() {
    let gecici = GeciciDizin::yeni("yanlis-parola");
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", 1_000);
    let hedef = gecici.birles("g1");
    let hata = ac(&kapsul, &hedef, YANLIS, &AcSecenekleri::default()).unwrap_err();
    assert!(
        matches!(hata, Hata::BozukKapsul(_)),
        "manifest etigi basarisiz olmaliydi, alinan: {hata:?}"
    );
    assert!(!hedef.exists(), "hatali parolada hicbir dosya yazilmamali");
}

#[test]
fn yanlis_parola_ve_bozuk_manifest_ayni_mesaji_verir() {
    // Kriptografik ayrim yapilamaz; kullaniciya tek bir birlestirilmis mesaj gider.
    let gecici = GeciciDizin::yeni("ayirt-edilemez");
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", 1_000);
    let yanlis = ac(
        &kapsul,
        &gecici.birles("g1"),
        YANLIS,
        &AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        },
    )
    .unwrap_err()
    .to_string();
    bayt_cevir(&kapsul, BASLIK + 2); // manifestin ilk bayti
    let bozuk = ac(
        &kapsul,
        &gecici.birles("g2"),
        PAROLA,
        &AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        },
    )
    .unwrap_err()
    .to_string();
    assert_eq!(
        yanlis, bozuk,
        "parola hatasi ile manifest bozuklugu ayirt edilememeli"
    );
    let sizinti = String::from_utf8_lossy(YANLIS).to_string();
    assert!(!yanlis.contains(&sizinti), "mesaj parolayi sizdirmemeli");
}

#[test]
fn sifre_metninde_bir_bit_cevirme_etik_dogrulamayi_bozar() {
    let gecici = GeciciDizin::yeni("bit-cevirme");
    let boyut = 1_000;
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", boyut);
    let payload = payload_baslangici(&kapsul, boyut);
    bayt_cevir(&kapsul, payload + 12 + 4 + 10); // sifre metninin 11. bayti
                                                // Kuyruk ozeti devre disi birakilir: aksi halde SHA-512 hatasi, hatanin
                                                // yerini bildiren parca bilgisini gizler.
    let hata = ac(
        &kapsul,
        &gecici.birles("g"),
        PAROLA,
        &AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        },
    )
    .unwrap_err();
    assert!(matches!(hata, Hata::BozukParca { .. }), "alinan: {hata:?}");
}

#[test]
fn bozuk_etik_dogrulamayi_bozar() {
    let gecici = GeciciDizin::yeni("bozuk-etik");
    let boyut = 1_000;
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", boyut);
    let payload = payload_baslangici(&kapsul, boyut);
    // Etiket parcanin son 16 bayti.
    let toplam = fs::metadata(&kapsul).unwrap().len();
    bayt_cevir(&kapsul, toplam - KUYRUK - 1);
    let hata = ac(
        &kapsul,
        &gecici.birles("g"),
        PAROLA,
        &AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        },
    )
    .unwrap_err();
    assert!(matches!(hata, Hata::BozukParca { .. }), "alinan: {hata:?}");
    let _ = payload;
}

#[test]
fn parca_sirasi_karistirilirsa_acma_basarisiz_olur() {
    // Iki parca; ikisinin sifre metni yer degistirilir. Ek veri (dosya sira,
    // parca sira) ve etiket ikisini de reddeder.
    let gecici = GeciciDizin::yeni("parca-sirasi");
    let boyut = 2 * KUCUK_PARCA as usize + 500;
    let kaynak = gecici.yaz("a.bin", &veri(boyut, 23));
    let kapsul = gecici.birles("a.sbx");
    muhurle(&kaynak, &kapsul, PAROLA, &hizli()).unwrap();

    let payload = payload_baslangici_cok_parca(&kapsul, 3, boyut as u64);
    // Ilk parcannin kayit uzunlugu: 12 + 4 + 512KiB + 16
    let kayit1 = 12 + 4 + KUCUK_PARCA + 16;
    let kayit2 = 12 + 4 + 500 + 16;
    let bir_ba = payload + 12 + 4;
    let iki_ba = payload + kayit1 as u64 + 12 + 4;
    let mut bayt = fs::read(&kapsul).unwrap();
    let uzunluk = std::cmp::min(KUCUK_PARCA as usize, 500);
    let blok1: Vec<u8> = bayt[bir_ba as usize..bir_ba as usize + uzunluk].to_vec();
    let blok2: Vec<u8> = bayt[iki_ba as usize..iki_ba as usize + uzunluk].to_vec();
    bayt[bir_ba as usize..bir_ba as usize + uzunluk].copy_from_slice(&blok2);
    bayt[iki_ba as usize..iki_ba as usize + uzunluk].copy_from_slice(&blok1);
    fs::write(&kapsul, &bayt).unwrap();

    let hata = ac(
        &kapsul,
        &gecici.birles("g"),
        PAROLA,
        &AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        },
    )
    .unwrap_err();
    assert!(matches!(hata, Hata::BozukParca { .. }), "alinan: {hata:?}");
    let _ = kayit2;
}

#[test]
fn kesik_kapsul_reddedilir() {
    let gecici = GeciciDizin::yeni("kesik");
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", 4_000);
    let bayt = fs::read(&kapsul).unwrap();
    // Yarisi kesiliyor.
    fs::write(&kapsul, &bayt[..bayt.len() / 2]).unwrap();
    assert!(ac(
        &kapsul,
        &gecici.birles("g"),
        PAROLA,
        &AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        }
    )
    .is_err());

    // Yalnizca sabit basliktan kisa bir dosya.
    fs::write(&kapsul, &bayt[..40]).unwrap();
    assert!(ac(
        &kapsul,
        &gecici.birles("g2"),
        PAROLA,
        &AcSecenekleri::default()
    )
    .is_err());
}

#[test]
fn sona_eklenen_bayt_kapsulu_gecersiz_kilar() {
    let gecici = GeciciDizin::yeni("ek-bayt");
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", 1_000);
    let mut bayt = fs::read(&kapsul).unwrap();
    bayt.extend_from_slice(b"sonradan eklenmis veri");
    fs::write(&kapsul, &bayt).unwrap();
    let hata = ac(
        &kapsul,
        &gecici.birles("g"),
        PAROLA,
        &AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        },
    )
    .unwrap_err();
    assert!(matches!(hata, Hata::BozukKapsul(_)), "alinan: {hata:?}");
}

#[test]
fn bozuk_sihirli_sayi_reddedilir() {
    let gecici = GeciciDizin::yeni("sihirli");
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", 1_000);
    bayt_cevir(&kapsul, 0);
    assert!(ac(
        &kapsul,
        &gecici.birles("g"),
        PAROLA,
        &AcSecenekleri::default()
    )
    .is_err());
}

#[test]
fn bozuk_bicim_surumu_reddedilir() {
    let gecici = GeciciDizin::yeni("surum");
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", 1_000);
    let mut bayt = fs::read(&kapsul).unwrap();
    bayt[4] = 0x09;
    fs::write(&kapsul, &bayt).unwrap();
    assert!(ac(
        &kapsul,
        &gecici.birles("g"),
        PAROLA,
        &AcSecenekleri::default()
    )
    .is_err());
}

#[test]
fn kuyruk_ozeti_bozulunca_acma_reddedilir() {
    let gecici = GeciciDizin::yeni("kuyruk-bozuk");
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", 1_000);
    let toplam = fs::metadata(&kapsul).unwrap().len();
    bayt_cevir(&kapsul, toplam - 1);
    assert!(ac(
        &kapsul,
        &gecici.birles("g"),
        PAROLA,
        &AcSecenekleri::default()
    )
    .is_err());
    // Parca etikleri saglam olsa bile kuyruk ozeti butunluk kaniti vermedigi icin
    // varsayilan acma reddedilir (rapor b10 "Kapsul butunlugu" kabul kriteri).
    assert!(ac(
        &kapsul,
        &gecici.birles("g2"),
        PAROLA,
        &AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        }
    )
    .is_ok());
}

#[test]
fn var_olan_kapsulun_uzerine_yazilmaz() {
    let gecici = GeciciDizin::yeni("uzerine-yazma");
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", 500);
    let once = fs::read(&kapsul).unwrap();
    let hata = muhurle(&kapsul, &kapsul, PAROLA, &hizli()).unwrap_err();
    assert!(matches!(hata, Hata::VarOluyor(_)), "alinan: {hata:?}");
    assert_eq!(fs::read(&kapsul).unwrap(), once, "kapsul degismemeli");
}

#[test]
fn var_olan_hedef_uzerine_yazilmaz() {
    let gecici = GeciciDizin::yeni("hedef-var");
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", 500);
    let hedef = gecici.yaz("g", b"var olan icerik");
    let hata = ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap_err();
    assert!(matches!(hata, Hata::VarOluyor(_)), "alinan: {hata:?}");
    assert_eq!(fs::read(&hedef).unwrap(), b"var olan icerik");
}

#[test]
fn var_olan_hedef_ustune_yaz_bayragi_ile_guncellenir() {
    let gecici = GeciciDizin::yeni("ustune-yaz-bayragi");
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", 500);
    let hedef = gecici.yaz("g", b"eski");
    ac(
        &kapsul,
        &hedef,
        PAROLA,
        &AcSecenekleri {
            ustune_yaz: true,
            ..AcSecenekleri::default()
        },
    )
    .unwrap();
    assert_eq!(fs::read(&hedef).unwrap(), veri(500, 17));
}

static IPTAL_SAYACI: AtomicU64 = AtomicU64::new(0);

#[test]
fn iptal_edilen_muhurlenmede_gecici_dosya_silinir() {
    let gecici = GeciciDizin::yeni("iptal");
    let boyut = 3 * KUCUK_PARCA as usize + 10;
    let kaynak = gecici.yaz("a.bin", &veri(boyut, 31));
    let kapsul = gecici.birles("a.sbx");
    let gecici_yol = gecici.birles("a.sbx.sbxtmp");

    let secenek = MuhurSecenekleri {
        parca_boyutu: KUCUK_PARCA,
        argon2: hizli_argon2(),
        ustune_yaz: false,
        devam: false,
        ilerleme: Some(Arc::new(|ilerleme: sealedbox::akis::Ilerleme| {
            // Ikinci parcadan sonra islemi durdur: gercek bir kesinti benzetimi.
            if ilerleme.asama == "sifreleniyor" && ilerleme.parca == 2 {
                IPTAL_SAYACI.fetch_add(1, Ordering::Relaxed);
                return Err(Hata::Iptal);
            }
            Ok(())
        })),
    };
    let hata = muhurle(&kaynak, &kapsul, PAROLA, &secenek).unwrap_err();
    assert!(matches!(hata, Hata::Iptal), "alinan: {hata:?}");
    assert!(!kapsul.exists(), "yarim kapsul olusmamali");
    assert!(
        !gecici_yol.exists(),
        "devam istenmedigi icin gecici dosya silinmeli"
    );
    assert_eq!(IPTAL_SAYACI.load(Ordering::Relaxed), 1);
}

#[test]
fn bos_parola_reddedilir() {
    let gecici = GeciciDizin::yeni("bos-parola");
    let kaynak = gecici.yaz("a.txt", b"x");
    let hata = muhurle(&kaynak, &gecici.birles("a.sbx"), b"", &hizli()).unwrap_err();
    assert!(matches!(hata, Hata::BozukArguman(_)));
}

#[test]
fn gecersiz_parca_boyutu_reddedilir() {
    let gecici = GeciciDizin::yeni("kucuk-parca");
    let kaynak = gecici.yaz("a.txt", b"x");
    let secenek = MuhurSecenekleri {
        parca_boyutu: 1_024,
        argon2: hizli_argon2(),
        ..MuhurSecenekleri::default()
    };
    let hata = muhurle(&kaynak, &gecici.birles("a.sbx"), PAROLA, &secenek).unwrap_err();
    assert!(matches!(hata, Hata::BozukArguman(_)), "alinan: {hata:?}");
    // 1 KiB, rapor b10'daki 512 KiB alt sinirinin altinda.
}

#[test]
fn gecersiz_argon2_parametresi_reddedilir() {
    let gecici = GeciciDizin::yeni("kotu-argon2");
    let kaynak = gecici.yaz("a.txt", b"x");
    let secenek = MuhurSecenekleri {
        parca_boyutu: KUCUK_PARCA,
        argon2: sealedbox::Argon2Ayar {
            bellek_kib: 100_000_000,
            tur: 3,
            yol: 4,
        },
        ..MuhurSecenekleri::default()
    };
    let hata = muhurle(&kaynak, &gecici.birles("a.sbx"), PAROLA, &secenek).unwrap_err();
    assert!(matches!(hata, Hata::BozukArguman(_)), "alinan: {hata:?}");
}

#[test]
fn dogrulama_butun_kapsulu_cozmeden_basar() {
    let gecici = GeciciDizin::yeni("dogrulama");
    let boyut = 2 * KUCUK_PARCA as usize + 7;
    gecici.yaz("agac/a.bin", &veri(boyut, 41));
    gecici.yaz("agac/b.txt", b"kisa");
    let kapsul = gecici.birles("agac.sbx");
    muhurle(&gecici.birles("agac"), &kapsul, PAROLA, &hizli()).unwrap();
    let rapor = sealedbox::dogrulama::dogrula(&kapsul, PAROLA).unwrap();
    // a.bin: 2*512 KiB + 7 -> 3 parca; b.txt: 1 parca
    assert_eq!(rapor.dogrulanan_parca, 4);
    assert_eq!(rapor.dogrulanan_bayt, boyut as u64 + 4);
    assert_eq!(rapor.dosya_sayisi, 2);
    assert_eq!(rapor.sonuc, "tamam");
    assert!(rapor.kuyruk_ozeti_dogrulandi);
}

#[test]
fn dogrulama_hatali_parolada_basarisiz_olur() {
    let gecici = GeciciDizin::yeni("dogrulama-hata");
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", 100);
    assert!(sealedbox::dogrulama::dogrula(&kapsul, YANLIS).is_err());
}

#[test]
fn dogrulama_bozuk_parcada_konumu_bildirir() {
    let gecici = GeciciDizin::yeni("dogrulama-konum");
    let boyut = 1_000;
    let kapsul = tek_parcali_kapsul(&gecici, "a.txt", boyut);
    let payload = payload_baslangici(&kapsul, boyut);
    bayt_cevir(&kapsul, payload + 12 + 4 + 5);
    let hata = sealedbox::dogrulama::dogrula(&kapsul, PAROLA).unwrap_err();
    match hata {
        Hata::BozukParca { parca, dosya } => {
            assert_eq!(parca, 0);
            assert_eq!(dosya, "a.txt");
        }
        diger => panic!("beklenmeyen hata: {diger:?}"),
    }
}
