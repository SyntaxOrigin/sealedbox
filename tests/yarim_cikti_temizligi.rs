//! Başarısız çözmede **yarım çıktı bırakılmaması** testleri.
//!
//! `ac` parçaları tek tek doğrulayıp diske yazar. On parçanın beşincisinin
//! etiketi tutmazsa ilk dört dosya diske tam olarak yazılmış, beşinci dosya
//! yarım kalmış hâlde geriye kalır. Bu, iki ayrı sorundur:
//!
//! 1. **Veri güvenliği:** hassas içeriğin eksik hâli diskte kalıcıdır ve
//!    kullanıcı hatadan sonra ağacı gerçek sanabilir.
//! 2. **Kurtarma:** `ac` tekrar çalıştırıldığında `create_new` "AlreadyExists"
//!    ile karşılaşır ve kullanıcı hiçbir ilerleme kaydedemez.
//!
//! Yöntem 09-timefold'un `veri_guvenligi.rs` desenini izler: komuttan önce ve
//! sonra **dokümante edilmiş ağaç dökümü** alınır ve karşılaştırılır.

mod yardimci;

use std::fs;
use std::path::Path;

use sealedbox::akis::{ac, muhurle, AcSecenekleri, MuhurSecenekleri};
use sealedbox::Hata;
use yardimci::{agac_dokumu, hizli_argon2, veri, GeciciDizin};

const PAROLA: &[u8] = b"yarim cikti temizligi!!";
const KUYRUK: u64 = 64;
const KUCUK_PARCA: u32 = 512 * 1024;

fn hizli() -> MuhurSecenekleri {
    MuhurSecenekleri {
        parca_boyutu: KUCUK_PARCA,
        argon2: hizli_argon2(),
        ..MuhurSecenekleri::default()
    }
}

/// Tek parçalı bir kaydın diskteki uzunluğu.
fn kayit_uzunlugu(boyut: usize) -> u64 {
    12 + 4 + boyut as u64 + 16
}

/// Kapsülü okur, bir bayt çevirir, geri yazar.
fn bayt_cevir(yol: &Path, ofset: u64) {
    let mut bayt = fs::read(yol).unwrap();
    let konum = usize::try_from(ofset).expect("u64 -> usize");
    assert!(konum < bayt.len(), "ofset kapsul disinda");
    bayt[konum] ^= 0x01;
    fs::write(yol, &bayt).unwrap();
}

/// Klasör kapsülü üretir; girdiler yola göre sıralı olduğu için payload'daki
/// kayıtlar da dosya adının alfabetik sırasına karşılık gelir.
///
/// Dönüş: (kapsül yolu, payload başlangıcı, her dosyanın şifreli bayt sayısı).
fn klasor_kapsulu(
    gecici: &GeciciDizin,
    ad: &str,
    boyutlar: &[usize],
) -> (std::path::PathBuf, u64, Vec<usize>) {
    let kok = gecici.dizin(ad);
    for (sira, boyut) in boyutlar.iter().enumerate() {
        fs::write(
            kok.join(format!("{sira}.bin")),
            veri(*boyut, 7 + sira as u8),
        )
        .unwrap();
    }
    let kapsul = gecici.birles(&format!("{ad}.sbx"));
    muhurle(&kok, &kapsul, PAROLA, &hizli()).unwrap();
    let payload: u64 = boyutlar.iter().map(|b| kayit_uzunlugu(*b)).sum();
    let baslangic = fs::metadata(&kapsul).unwrap().len() - KUYRUK - payload;
    (kapsul, baslangic, boyutlar.to_vec())
}

#[test]
fn etik_tutmayan_parcada_hicbir_cikti_dosyasi_kalmaz() {
    let gecici = GeciciDizin::yeni("yarim-agac");
    // Beş dosya, her biri tek parça. Sonuncunun etiketi bozulacak.
    let boyutlar = [1_000usize, 1_100, 1_200, 1_300, 1_400];
    let (kapsul, payload, boyutlar) = klasor_kapsulu(&gecici, "kaynak", &boyutlar);

    // Son kaydın etiketindeki tek bir baytı çevir.
    let onceki: u64 = boyutlar[..4].iter().map(|b| kayit_uzunlugu(*b)).sum();
    let son_kayit = payload + onceki;
    bayt_cevir(&kapsul, son_kayit + 12 + 4 + boyutlar[4] as u64 + 3);

    let hedef = gecici.dizin("geri");
    assert!(
        agac_dokumu(&hedef).is_empty(),
        "hedef denetim basinda bos olmali"
    );

    let hata = ac(
        &kapsul,
        &hedef,
        PAROLA,
        &AcSecenekleri {
            // Kuyruk ozeti devre disi: SHA-512 hatasi, hatanin yerini bildiren
            // parca bilgisini gizler ve yanlis hata turu elde edilir.
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        },
    )
    .unwrap_err();
    assert!(matches!(hata, Hata::BozukParca { .. }), "alinan: {hata:?}");

    let döküm = agac_dokumu(&hedef);
    assert!(
        döküm.is_empty(),
        "etik tutmayan parçada **hiçbir** çıktı dosyası diskte kalmamalı, \
         kalan: {döküm:?}"
    );
    assert!(
        !hedef.join("kaynak").exists(),
        "geri yuklenen kok agac tamamen kaldirilmalı"
    );
}

#[test]
fn etik_tutmayan_parcada_kok_dizin_ve_ara_dizinler_kalmaz() {
    let gecici = GeciciDizin::yeni("yarim-agac-derin");
    let kok = gecici.dizin("kaynak");
    // Girdiler yola gore sirali: alt dizin once, sonra dosyalar.
    let boyutlar = [900usize, 1_000, 1_100];
    for (sira, boyut) in boyutlar.iter().enumerate() {
        fs::write(
            kok.join(format!("{sira}.bin")),
            veri(*boyut, 5 + sira as u8),
        )
        .unwrap();
    }
    let kapsul = gecici.birles("kaynak.sbx");
    muhurle(&kok, &kapsul, PAROLA, &hizli()).unwrap();

    // Son kaydin etiketini boz.
    let payload: u64 = boyutlar.iter().map(|b| kayit_uzunlugu(*b)).sum();
    let baslangic = fs::metadata(&kapsul).unwrap().len() - KUYRUK - payload;
    let onceki: u64 = boyutlar[..2].iter().map(|b| kayit_uzunlugu(*b)).sum();
    bayt_cevir(&kapsul, baslangic + onceki + 12 + 4 + boyutlar[2] as u64);

    let hedef = gecici.dizin("geri");
    let hata = ac(
        &kapsul,
        &hedef,
        PAROLA,
        &AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        },
    )
    .unwrap_err();
    assert!(matches!(hata, Hata::BozukParca { .. }), "alinan: {hata:?}");
    assert!(
        agac_dokumu(&hedef).is_empty(),
        "dizin girdileri de dahil hicbir artik kalmamali"
    );
}

#[test]
fn tek_dosya_kapsulunde_yarim_dosya_kalmaz() {
    // Tek dosya kapsulunde agac yoktur; yarim yazilmis dosyanin **kendisi**
    // silinmelidir, aksi halde yeniden deneme `create_new` ile kalici olarak
    // kilitlenir.
    let gecici = GeciciDizin::yeni("yarim-dosya");
    let boyut = 1_500usize;
    let kaynak = gecici.yaz("a.bin", &veri(boyut, 9));
    let kapsul = gecici.birles("a.sbx");
    muhurle(&kaynak, &kapsul, PAROLA, &hizli()).unwrap();

    let payload = fs::metadata(&kapsul).unwrap().len() - KUYRUK - kayit_uzunlugu(boyut);
    bayt_cevir(&kapsul, payload + 12 + 4 + 5);

    let hedef = gecici.birles("geri.bin");
    let hata = ac(
        &kapsul,
        &hedef,
        PAROLA,
        &AcSecenekleri {
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        },
    )
    .unwrap_err();
    assert!(matches!(hata, Hata::BozukParca { .. }), "alinan: {hata:?}");
    assert!(
        !hedef.exists(),
        "yarım yazılmış tek dosya diskte bırakılmamalı"
    );
}

#[test]
fn temizlik_sonrasi_ac_tekrar_calisabilir() {
    // Kurtarma yolu: hata agaci temizledigi icin ayni hedef yeniden
    // denendiğinde `VarOluyor` degil, dogrusal bir parca hatasi gelir.
    let gecici = GeciciDizin::yeni("yarim-tekrar");
    let boyutlar = [1_000usize, 1_200];
    let (kapsul, payload, boyutlar) = klasor_kapsulu(&gecici, "kaynak", &boyutlar);
    bayt_cevir(&kapsul, payload + 12 + 4 + boyutlar[1] as u64 + 2);

    let hedef = gecici.dizin("geri");
    for _ in 0..2 {
        let hata = ac(
            &kapsul,
            &hedef,
            PAROLA,
            &AcSecenekleri {
                kuyruk_ozetini_dogrula: false,
                ..AcSecenekleri::default()
            },
        )
        .unwrap_err();
        assert!(
            matches!(hata, Hata::BozukParca { .. }),
            "ikinci denemede 'VarOluyor' gelmemeli, alinan: {hata:?}"
        );
    }
    assert!(agac_dokumu(&hedef).is_empty());
}

#[test]
fn ustune_yazma_hatasinda_yarim_agac_kalmaz() {
    // `--ustune-yaz` yolu hedef agaci **once** siler; yeni agac olusurken hata
    // verirse diskte hicbir sey kalmamalidir. Iki kapsul de ayni kok adi
    // (`kaynak`) tasiyan kaynaklardan uretilir, aksi halde hedef agaclar
    // carpismaz ve senaryo olusmaz.
    let gecici = GeciciDizin::yeni("ustune-yaz-yarim");

    // 1) Saglam kapsul: kok adi `kaynak`.
    let iyi_kok = gecici.dizin("iyi/kaynak");
    fs::write(iyi_kok.join("x.bin"), veri(1_000, 3)).unwrap();
    let saglam = gecici.birles("saglam.sbx");
    muhurle(&iyi_kok, &saglam, PAROLA, &hizli()).unwrap();

    // 2) Bozuk kapsul: ayni kok adi, son parcannin etiketi bozuk.
    let bozuk_boyutlar = [1_000usize, 1_300];
    let (bozuk, payload, boyutlar) = klasor_kapsulu(&gecici, "kaynak", &bozuk_boyutlar);
    bayt_cevir(&bozuk, payload + 12 + 4 + boyutlar[1] as u64 + 1);

    // 3) Once saglam agaci geri yukle.
    let hedef = gecici.dizin("geri");
    ac(&saglam, &hedef, PAROLA, &AcSecenekleri::default()).unwrap();
    let onceki = agac_dokumu(&hedef);
    assert!(
        onceki.contains_key("kaynak/x.bin"),
        "saglam agac geri yuklenmis olmali, döküm: {onceki:?}"
    );

    // 4) Bozuk kapsulu ustune yaz: eski agac silinir, yeni agac yarim kalir.
    let hata = ac(
        &bozuk,
        &hedef,
        PAROLA,
        &AcSecenekleri {
            ustune_yaz: true,
            kuyruk_ozetini_dogrula: false,
            ..AcSecenekleri::default()
        },
    )
    .unwrap_err();
    assert!(matches!(hata, Hata::BozukParca { .. }), "alinan: {hata:?}");
    let sonrasi = agac_dokumu(&hedef);
    assert!(
        sonrasi.is_empty(),
        "ustune yazma basarisizliginda ne yarim yeni agac ne de eski agac \
         kalmamali, döküm: {sonrasi:?}"
    );
}
