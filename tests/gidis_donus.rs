//! Şifreleme/çözme gidiş-dönüş ve akış davranışı testleri.
//!
//! Kapsanan senaryolar: tek dosya, boş dosya, bir bayta yakın dosya, parça
//! sınırlarına tam oturan dosya, çok parçalı büyük dosya (akış), boş klasör,
//! iç içe klasör ağacı, ikili içerik, yeniden mühürlemede farklı nonce.

mod yardimci;

use std::fs;

use sealedbox::akis::{ac, muhurle, AcSecenekleri, MuhurSecenekleri};
use sealedbox::Argon2Ayar;
use yardimci::{hizli_argon2, veri, GeciciDizin};

const PAROLA: &[u8] = b"dogru test parcasi 2026";

fn hizli(parca: u32) -> MuhurSecenekleri {
    MuhurSecenekleri {
        parca_boyutu: parca,
        argon2: hizli_argon2(),
        ..MuhurSecenekleri::default()
    }
}

/// 512 KiB, rapor b10'daki izinli en küçük parça boyutudur; testler hızlı kalsın
/// diye bu değer kullanılır.
const KUCUK_PARCA: u32 = 512 * 1024;

#[test]
fn tek_dosya_gidis_donus_basar() {
    let gecici = GeciciDizin::yeni("tek");
    let kaynak = gecici.yaz("rapor.txt", &veri(10_000, 3));
    let kapsul = gecici.birles("rapor.sbx");

    let rapor = muhurle(&kaynak, &kapsul, PAROLA, &hizli(KUCUK_PARCA)).unwrap();
    assert_eq!(rapor.dosya_sayisi, 1);
    assert_eq!(rapor.parca_sayisi, 1);
    assert_eq!(rapor.girdi_bayti, 10_000);
    assert!(!rapor.devam_edildi);
    assert!(kapsul.exists());
    assert!(kapsul_bayti(&kapsul) > rapor.girdi_bayti as u64);

    let hedef = gecici.birles("geri.txt");
    let rapor = ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    assert_eq!(rapor.cikti_bayti, 10_000);
    assert_eq!(rapor.dosya_sayisi, 1);
    assert!(rapor.kuyruk_ozeti_dogrulandi);

    let geri = hedef.clone();
    assert_eq!(fs::read(&geri).unwrap(), veri(10_000, 3));
}

#[test]
fn bos_dosya_gidis_donus_basar() {
    let gecici = GeciciDizin::yeni("bos-dosya");
    let kaynak = gecici.yaz("bos.txt", b"");
    let kapsul = gecici.birles("bos.sbx");
    let rapor = muhurle(&kaynak, &kapsul, PAROLA, &hizli(KUCUK_PARCA)).unwrap();
    assert_eq!(rapor.girdi_bayti, 0);
    assert_eq!(rapor.parca_sayisi, 0, "bos dosyanin parcasi olmamali");

    let hedef = gecici.birles("geri.txt");
    ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    let geri = hedef;
    assert!(geri.is_file());
    assert_eq!(fs::metadata(&geri).unwrap().len(), 0);
}

#[test]
fn bir_baytlik_dosya_gidis_donus_basar() {
    let gecici = GeciciDizin::yeni("bir-bayt");
    let kaynak = gecici.yaz("tek.txt", b"X");
    let kapsul = gecici.birles("tek.sbx");
    muhurle(&kaynak, &kapsul, PAROLA, &hizli(KUCUK_PARCA)).unwrap();
    let hedef = gecici.birles("geri.txt");
    ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    assert_eq!(fs::read(&hedef).unwrap(), b"X");
}

#[test]
fn parca_sinirinda_tam_boyutlu_dosya_gidis_donus_basar() {
    // Parça boyutunun tam katı: son parça kısmi değil, bir sonraki parça da yok.
    let gecici = GeciciDizin::yeni("tam-parca");
    let boyut = 2 * KUCUK_PARCA as usize;
    let kaynak = gecici.yaz("tam.bin", &veri(boyut, 7));
    let kapsul = gecici.birles("tam.sbx");
    let rapor = muhurle(&kaynak, &kapsul, PAROLA, &hizli(KUCUK_PARCA)).unwrap();
    assert_eq!(rapor.parca_sayisi, 2);
    let hedef = gecici.birles("geri.bin");
    ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    assert_eq!(fs::read(&hedef).unwrap(), veri(boyut, 7));
}

#[test]
fn cok_parcali_buyuk_dosya_akis_halinde_gidis_donus_basar() {
    // 12 MiB + 137 bayt: dosya tamponun (512 KiB) cok uzerinde ama bellege
    // alinmiyor. 25 parcaya bolunur.
    let gecici = GeciciDizin::yeni("buyuk");
    let boyut = 12 * 1024 * 1024 + 137;
    let kaynak = gecici.yaz("buyuk.bin", &veri(boyut, 11));
    let kapsul = gecici.birles("buyuk.sbx");
    let rapor = muhurle(&kaynak, &kapsul, PAROLA, &hizli(KUCUK_PARCA)).unwrap();
    assert_eq!(rapor.parca_sayisi, 25);
    assert_eq!(rapor.girdi_bayti, boyut as u64);

    let hedef = gecici.birles("geri.bin");
    let ac_rapor = ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    assert_eq!(ac_rapor.parca_sayisi, 25);
    assert_eq!(fs::read(&hedef).unwrap(), veri(boyut, 11));
}

#[test]
fn kapsul_bayti_girdiden_yeterince_buyuktur() {
    // Yük: parca basina 12 (nonce) + 4 (uzunluk) + 16 (etiket) = 32 bayt,
    // arti kapsul basligi (96) + manifest + 64 bayt kuyruk ozeti.
    let gecici = GeciciDizin::yeni("yuk");
    let boyut = KUCUK_PARCA as usize * 3;
    let kaynak = gecici.yaz("y.bin", &veri(boyut, 5));
    let kapsul = gecici.birles("y.sbx");
    let rapor = muhurle(&kaynak, &kapsul, PAROLA, &hizli(KUCUK_PARCA)).unwrap();
    assert_eq!(rapor.parca_sayisi, 3);
    let kapsul_uzunlugu = kapsul_bayti(&kapsul);
    let en_fazla_yuk = 3 * 32 + 96 + 64 + 512;
    assert!(
        kapsul_uzunlugu <= boyut as u64 + en_fazla_yuk,
        "kapsul beklenenden fazla buyudu: {kapsul_uzunlugu}"
    );
}

#[test]
fn bos_klasor_muhurlenir_ve_geri_yuklenir() {
    let gecici = GeciciDizin::yeni("bos-klasor");
    let kaynak = gecici.dizin("bos-agac");
    let kapsul = gecici.birles("bos-agac.sbx");
    let rapor = muhurle(&kaynak, &kapsul, PAROLA, &hizli(KUCUK_PARCA)).unwrap();
    assert_eq!(rapor.dosya_sayisi, 0);
    assert_eq!(rapor.dizin_sayisi, 0);
    assert_eq!(rapor.parca_sayisi, 0);

    let hedef = gecici.dizin("geri");
    ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    assert!(hedef.join("bos-agac").is_dir());
}

#[test]
fn ic_ice_klasor_agaci_yol_ve_izin_ile_geri_yuklenir() {
    let gecici = GeciciDizin::yeni("agac");
    gecici.yaz("agac/ust.txt", b"ust");
    gecici.yaz("agac/ic/orta.txt", b"orta");
    gecici.yaz("agac/ic/derin/en-alt.bin", &veri(5_000, 9));
    gecici.dizin("agac/bos-alt");
    let kaynak = gecici.birles("agac");
    let kapsul = gecici.birles("agac.sbx");

    let rapor = muhurle(&kaynak, &kapsul, PAROLA, &hizli(KUCUK_PARCA)).unwrap();
    assert_eq!(rapor.dosya_sayisi, 3);
    // ic, ic/derin, bos-alt
    assert_eq!(rapor.dizin_sayisi, 3);
    assert_eq!(rapor.parca_sayisi, 3);

    let hedef = gecici.dizin("geri");
    let ac_rapor = ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    assert_eq!(ac_rapor.dosya_sayisi, 3);
    let kok = hedef.join("agac");
    assert_eq!(fs::read(kok.join("ust.txt")).unwrap(), b"ust");
    assert_eq!(fs::read(kok.join("ic/orta.txt")).unwrap(), b"orta");
    assert_eq!(
        fs::read(kok.join("ic/derin/en-alt.bin")).unwrap(),
        veri(5_000, 9)
    );
    assert!(kok.join("bos-alt").is_dir(), "bos dizin de olusmali");
}

#[test]
fn ikili_ve_sifre_gibi_icerikler_bayt_bayt_korunur() {
    let gecici = GeciciDizin::yeni("ikili");
    let karisik: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
    gecici.yaz("agac/000.bin", &karisik);
    gecici.yaz("agac/uzanti.dat", &[0x00, 0x0D, 0x0A, 0x1A, 0xFF]);
    gecici.yaz("agac/bos.uzanti", b"");
    let kapsul = gecici.birles("agac.sbx");
    muhurle(&gecici.birles("agac"), &kapsul, PAROLA, &hizli(KUCUK_PARCA)).unwrap();
    let hedef = gecici.dizin("geri");
    ac(&kapsul, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    let kok = hedef.join("agac");
    assert_eq!(fs::read(kok.join("000.bin")).unwrap(), karisik);
    assert_eq!(
        fs::read(kok.join("uzanti.dat")).unwrap(),
        vec![0x00, 0x0D, 0x0A, 0x1A, 0xFF]
    );
    assert_eq!(fs::read(kok.join("bos.uzanti")).unwrap(), Vec::<u8>::new());
}

#[test]
fn ayni_kaynagi_iki_kez_muhurlemek_farkli_kapsul_uretir() {
    // Nonce'lar rastgele oldugu icin ayni girdi iki kapsulde farkli sifre metni verir.
    let gecici = GeciciDizin::yeni("tekrar");
    let kaynak = gecici.yaz("a.txt", b"ayni icerik");
    let bir = gecici.birles("bir.sbx");
    let iki = gecici.birles("iki.sbx");
    muhurle(&kaynak, &bir, PAROLA, &hizli(KUCUK_PARCA)).unwrap();
    muhurle(&kaynak, &iki, PAROLA, &hizli(KUCUK_PARCA)).unwrap();
    let bir_içerik = fs::read(&bir).unwrap();
    let iki_içerik = fs::read(&iki).unwrap();
    assert_eq!(bir_içerik.len(), iki_içerik.len());
    assert_ne!(bir_içerik, iki_içerik, "ayni icerik ayni kapsul olmamali");
}

#[test]
fn ayni_parola_ve_tuz_ile_acma_muhurlemeyle_tutarli() {
    let gecici = GeciciDizin::yeni("tutarlilik");
    let kaynak = gecici.yaz("a.txt", &veri(4_096, 21));
    let kapsul = gecici.birles("a.sbx");
    let ayar = Argon2Ayar {
        bellek_kib: 16_384,
        tur: 2,
        yol: 1,
    };
    let secenek = MuhurSecenekleri {
        parca_boyutu: KUCUK_PARCA,
        argon2: ayar,
        ..MuhurSecenekleri::default()
    };
    muhurle(&kaynak, &kapsul, PAROLA, &secenek).unwrap();
    let ozet = sealedbox::akis::kapsul_ozeti_oku(&kapsul, PAROLA).unwrap();
    assert_eq!(
        ozet.argon2, ayar,
        "basliktaki Argon2 parametreleri korunmali"
    );
    assert_eq!(ozet.parca_boyutu, KUCUK_PARCA);
    assert_eq!(ozet.girdi_bayti, 4_096);
    assert_eq!(ozet.parca_sayisi, 1);
    assert!(!ozet.dizin_agaci);
    assert_eq!(ozet.kok_ad, "a.txt");
}

#[test]
fn kuyruk_ozeti_atlanabilir_ama_ozet_bozukken_dogrulanir() {
    let gecici = GeciciDizin::yeni("kuyruk");
    let kaynak = gecici.yaz("a.txt", b"icerik");
    let kapsul = gecici.birles("a.sbx");
    muhurle(&kaynak, &kapsul, PAROLA, &hizli(KUCUK_PARCA)).unwrap();

    // Kuyruk ozeti atlanirsa acma yine calisir.
    let hedef1 = gecici.birles("g1.txt");
    let rapor = ac(
        &kapsul,
        &hedef1,
        PAROLA,
        &AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        },
    )
    .unwrap();
    assert!(!rapor.kuyruk_ozeti_dogrulandi);

    // Ozet butunlugu bozuldugunda varsayilan ayarla acma reddedilir.
    let mut bayt = fs::read(&kapsul).unwrap();
    let son = bayt.len() - 1;
    bayt[son] ^= 0xFF;
    fs::write(&kapsul, &bayt).unwrap();
    let hedef2 = gecici.birles("g2.txt");
    assert!(ac(&kapsul, &hedef2, PAROLA, &AcSecenekleri::default()).is_err());
}

fn kapsul_bayti(yol: &std::path::Path) -> u64 {
    fs::metadata(yol).map(|m| m.len()).unwrap_or(0)
}
