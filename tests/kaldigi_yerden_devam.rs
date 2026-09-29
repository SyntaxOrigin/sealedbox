//! Kaldığı yerden devam (kesinti kurtarma) testleri.
//!
//! Rapor b03/S3 ve b16'nın yanıtı: mühürleme yarıda kesildiğinde kullanıcı
//! `--devam` ile kaldığı yerden sürdürebilir. Bu testler gerçek bir kesintiyi
//! ilerleme geri çağrısı aracılığıyla benzetir ve şu güvenlik sözleşmesini
//! sınar: devam sırasında **hiçbir nonce yeniden kullanılmaz**.

mod yardimci;

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sealedbox::akis::{ac, muhurle, AcSecenekleri, Ilerleme, MuhurSecenekleri};
use yardimci::{hizli_argon2, veri, GeciciDizin};

const PAROLA: &[u8] = b"devam testi parcasi";
const KUCUK_PARCA: u32 = 512 * 1024;

/// `n` parça yazıldıktan sonra işi durduran mühürleme seçeneği üretir.
fn durduran(n: u64) -> MuhurSecenekleri {
    MuhurSecenekleri {
        parca_boyutu: KUCUK_PARCA,
        argon2: hizli_argon2(),
        ustune_yaz: false,
        devam: true,
        ilerleme: Some(Arc::new(move |ilerleme: Ilerleme| {
            if ilerleme.asama == "sifreleniyor" && ilerleme.parca >= n {
                return Err(sealedbox::Hata::Iptal);
            }
            Ok(())
        })),
    }
}

#[test]
fn yarim_kalan_muhurlenmeden_sonra_kaldigi_yerden_devam_edilir() {
    let gecici = GeciciDizin::yeni("devam");
    let boyut = 4 * KUCUK_PARCA as usize + 123;
    let icerik = veri(boyut, 13);
    let kaynak = gecici.yaz("a.bin", &icerik);
    let kapsul = gecici.birles("a.sbx");
    let gecici_yol = gecici.birles("a.sbx.sbxtmp");

    // 1) Ikinci parcadan sonra kesinti.
    let hata = muhurle(&kaynak, &kapsul, PAROLA, &durduran(2)).unwrap_err();
    assert!(matches!(hata, sealedbox::Hata::Iptal));
    assert!(!kapsul.exists(), "kapsul olusmamali");
    assert!(gecici_yol.exists(), "gecici dosya korunmali");

    // 2) Ayni kaynaktan devam.
    let secenek = MuhurSecenekleri {
        parca_boyutu: KUCUK_PARCA,
        argon2: hizli_argon2(),
        devam: true,
        ..MuhurSecenekleri::default()
    };
    let rapor = muhurle(&kaynak, &kapsul, PAROLA, &secenek).unwrap();
    assert!(rapor.devam_edildi, "kaldigi yerden devam edilmis olmali");
    assert!(kapsul.exists());
    assert!(!gecici_yol.exists(), "gecici dosya tasinmali");

    // 3) Icerik bayt bayt ayni.
    let hedef = gecici.birles("geri.bin");
    ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    assert_eq!(fs::read(&hedef).unwrap(), icerik);
}

#[test]
fn devam_edilen_kapsul_tam_muhurlenmeyle_ayni_icerigi_verir() {
    let gecici = GeciciDizin::yeni("devam-karsilastir");
    let boyut = 3 * KUCUK_PARCA as usize + 1;
    let icerik = veri(boyut, 29);
    let kaynak = gecici.yaz("a.bin", &icerik);
    let tam_secenek = MuhurSecenekleri {
        parca_boyutu: KUCUK_PARCA,
        argon2: hizli_argon2(),
        ..MuhurSecenekleri::default()
    };

    let kesik = gecici.birles("kesik.sbx");
    let _ = muhurle(&kaynak, &kesik, PAROLA, &durduran(1));
    muhurle(&kaynak, &kesik, PAROLA, &tam_secenek).unwrap();

    let tam = gecici.birles("tam.sbx");
    muhurle(&kaynak, &tam, PAROLA, &tam_secenek).unwrap();

    let g1 = gecici.birles("g1.bin");
    let g2 = gecici.birles("g2.bin");
    ac(&kesik, &g1, PAROLA, &AcSecenekleri::default()).unwrap();
    ac(&tam, &g2, PAROLA, &AcSecenekleri::default()).unwrap();
    assert_eq!(fs::read(&g1).unwrap(), icerik);
    assert_eq!(fs::read(&g2).unwrap(), icerik);
    // Kapsul boyutlari esit olmali: nonce'lar rastgele oldugu icin *icerik* farkli,
    // ama yapilandirma ve yuke ayni.
    assert_eq!(
        fs::metadata(&kesik).unwrap().len(),
        fs::metadata(&tam).unwrap().len()
    );
}

#[test]
fn devam_bayragi_verilmeden_gecici_dosya_silinir_ve_sifirdan_baslanir() {
    let gecici = GeciciDizin::yeni("devamsiz");
    let boyut = 3 * KUCUK_PARCA as usize;
    let icerik = veri(boyut, 37);
    let kaynak = gecici.yaz("a.bin", &icerik);
    let kapsul = gecici.birles("a.sbx");
    let gecici_yol = gecici.birles("a.sbx.sbxtmp");

    let secenek = MuhurSecenekleri {
        parca_boyutu: KUCUK_PARCA,
        argon2: hizli_argon2(),
        devam: false,
        ilerleme: Some(Arc::new(|i: Ilerleme| {
            if i.asama == "sifreleniyor" && i.parca == 1 {
                return Err(sealedbox::Hata::Iptal);
            }
            Ok(())
        })),
        ..MuhurSecenekleri::default()
    };
    assert!(muhurle(&kaynak, &kapsul, PAROLA, &secenek).is_err());
    assert!(!gecici_yol.exists(), "devam istenmedigi icin silinmeli");

    // Sifirdan yeniden muhurle.
    let rapor = muhurle(
        &kaynak,
        &kapsul,
        PAROLA,
        &MuhurSecenekleri {
            parca_boyutu: KUCUK_PARCA,
            argon2: hizli_argon2(),
            ..MuhurSecenekleri::default()
        },
    )
    .unwrap();
    assert!(!rapor.devam_edildi);
    let hedef = gecici.birles("g.bin");
    ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    assert_eq!(fs::read(&hedef).unwrap(), icerik);
}

static DEVRAN_KEZ: AtomicU64 = AtomicU64::new(0);

#[test]
fn kaynak_degisirse_devam_reddedilir_ve_yeniden_baslanir() {
    let gecici = GeciciDizin::yeni("devam-kaynak-degisti");
    let boyut = 3 * KUCUK_PARCA as usize + 999;
    let kaynak = gecici.yaz("a.bin", &veri(boyut, 41));
    let kapsul = gecici.birles("a.sbx");
    let _ = muhurle(&kaynak, &kapsul, PAROLA, &durduran(1));
    assert!(gecici.birles("a.sbx.sbxtmp").exists());

    // Kaynak dosya degisti: parca duzeni degistigi icin devam reddedilir.
    fs::write(&kaynak, veri(boyut + 4096, 41)).unwrap();
    DEVRAN_KEZ.fetch_add(1, Ordering::Relaxed);
    let rapor = muhurle(
        &kaynak,
        &kapsul,
        PAROLA,
        &MuhurSecenekleri {
            parca_boyutu: KUCUK_PARCA,
            argon2: hizli_argon2(),
            devam: true,
            ..MuhurSecenekleri::default()
        },
    )
    .unwrap();
    assert!(!rapor.devam_edildi, "kaynak degistiyse devam edilmemeli");
    let hedef = gecici.birles("g.bin");
    ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    assert_eq!(fs::metadata(&hedef).unwrap().len(), (boyut + 4096) as u64);
}

#[test]
fn yarim_yazilmis_gecici_dosya_yarim_parca_yazmaz() {
    // Kesinti, bir parcayi yazarken olursa dosya sonunda yarim bir parca kalir.
    // Devam bu artigi **kirpar**: boylece hicbir parca ne eksik ne fazla yazilir
    // ve yarim parcanin nonce'u hicbir sifre metniyle eslesmez.
    let gecici = GeciciDizin::yeni("yarim-parca");
    let boyut = 3 * KUCUK_PARCA as usize;
    let icerik = veri(boyut, 43);
    let kaynak = gecici.yaz("a.bin", &icerik);
    let kapsul = gecici.birles("a.sbx");
    let _ = muhurle(&kaynak, &kapsul, PAROLA, &durduran(1));

    let gecici_yol = gecici.birles("a.sbx.sbxtmp");
    let mut bayt = fs::read(&gecici_yol).unwrap();
    bayt.extend_from_slice(&[0xAB; 137]); // yarim parca
    fs::write(&gecici_yol, &bayt).unwrap();

    let rapor = muhurle(
        &kaynak,
        &kapsul,
        PAROLA,
        &MuhurSecenekleri {
            parca_boyutu: KUCUK_PARCA,
            argon2: hizli_argon2(),
            devam: true,
            ..MuhurSecenekleri::default()
        },
    )
    .unwrap();
    assert!(
        rapor.devam_edildi,
        "gecerli parca sinirindan devam edilmeli"
    );
    let hedef = gecici.birles("g.bin");
    ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    assert_eq!(fs::read(&hedef).unwrap(), icerik);
    // Kapsul, yarim parca artigi olmadan tam boyutta olmali: 3 parcann
    // kayit yuku (3 * 32) + sabit baslik (96) + kuyruk ozeti (64) + sifre metni.
    let beklenen = 96 + 64 + 3 * 32 + boyut as u64;
    assert!(fs::metadata(&kapsul).unwrap().len() >= beklenen);
    let tam_referans = gecici.birles("referans.sbx");
    muhurle(
        &kaynak,
        &tam_referans,
        PAROLA,
        &MuhurSecenekleri {
            parca_boyutu: KUCUK_PARCA,
            argon2: hizli_argon2(),
            ..MuhurSecenekleri::default()
        },
    )
    .unwrap();
    assert_eq!(
        fs::metadata(&kapsul).unwrap().len(),
        fs::metadata(&tam_referans).unwrap().len(),
        "yarim parca artigi kirpilmamis"
    );
}
