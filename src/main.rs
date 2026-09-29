//! `mseal` komut satırı arayüzü.
//!
//! Bu dosya yalnızca çekirdeği sarar: argüman ayrıştırma, parola okuma,
//! çıktı biçimlendirme ve çıkış kodu. Kriptografik mantığın tamamı
//! `sealedbox` kütüphanesinde (`src/lib.rs`) yaşar ve orada test edilir.
//!
//! Parola hiçbir zaman komut satırı argümanı olarak **zorunlu** kabul edilmez
//! (işlem listelerinde ve kabuk geçmişinde görünür); varsayılan kaynak
//! `MSEAL_PAROLA` ortam değişkenidir.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use sealedbox::akis::{self, AcSecenekleri, IlerlemeGeriCagri, MuhurSecenekleri};
use sealedbox::hata::Hata;
use sealedbox::kapsul::{EN_BUYUK_PARCA, EN_KUCUK_PARCA, VARSAYILAN_PARCA};
use sealedbox::kripto::Argon2Ayar;
use serde::Serialize;

/// Parolanın okunabileceği varsayılan ortam değişkeni.
const PAROLA_DEGISKENI: &str = "MSEAL_PAROLA";

/// MühürKasa (SealedBox) komut satırı aracı.
#[derive(Debug, Parser)]
#[command(
    name = "mseal",
    version,
    about = "Akis halinde AES-256-GCM ile buyuk dosya ve klasor agaclarini muhurler."
)]
struct KomutSatiri {
    #[command(subcommand)]
    alt_komut: AltKomut,
}

#[derive(Debug, Subcommand)]
enum AltKomut {
    /// Bir dosyayi veya klasor agacini kapsul olarak muhurler.
    Sifrele {
        /// Muhurlenecek dosya veya klasor.
        kaynak: PathBuf,
        /// Yazilacak kapsul dosyasi.
        kapsul: PathBuf,
        #[command(flatten)]
        sifreleme: SifrelemeSecenekleri,
        #[command(flatten)]
        ortak: OrtakSecenekler,
    },
    /// Bir kapsulu dogrular ve icerigini hedefe geri yukler.
    Ac {
        /// Acilacak kapsul dosyasi.
        kapsul: PathBuf,
        /// Icerigin yazilacagi dizin; kapsul icindeki kok dizin buraya olusturulur.
        hedef: PathBuf,
        /// Var olan kapsule uzerine yazilsin mi.
        #[arg(long)]
        ustune_yaz: bool,
        /// Kapsulun SHA-512 kuyruk ozeti denetlenmesin mi (daha hizli, daha zayif).
        #[arg(long)]
        kuyruk_ozeti_atla: bool,
        #[command(flatten)]
        ortak: OrtakSecenekler,
    },
    /// Kapsulun icerigini listeler; duz metin cozulmez.
    Listele {
        /// Listelenecek kapsul dosyasi.
        kapsul: PathBuf,
        #[command(flatten)]
        ortak: OrtakSecenekler,
    },
    /// Kapsul basligini ve ozet bilgileri gosterir.
    #[command(name = "mseal-info", alias = "bilgi")]
    Bilgi {
        /// Bilgisi okunacak kapsul dosyasi.
        kapsul: PathBuf,
        #[command(flatten)]
        ortak: OrtakSecenekler,
    },
    /// Kapsulun butunluk etiketlerini cozmadan dogrular.
    #[command(name = "mseal-verify", alias = "dogrula")]
    Dogrula {
        /// Dogrulanacak kapsul dosyasi.
        kapsul: PathBuf,
        #[command(flatten)]
        ortak: OrtakSecenekler,
    },
}

#[derive(Debug, Args)]
struct OrtakSecenekler {
    /// Parolayi bu ortam degiskeninden oku.
    #[arg(long, value_name = "DEGISKEN")]
    parola_degiskeni: Option<String>,
    /// Parolayi bu dosyadan oku ( satir sonu kirpilir).
    #[arg(long, value_name = "DOSYA")]
    parola_dosyasi: Option<PathBuf>,
    /// Parolayi standart girdiden oku.
    #[arg(long)]
    parola_stdin: bool,
    /// Parolayi bu deger olarak kullan; kabuk gecmisine yazilir, tercih etmeyin.
    #[arg(long, value_name = "PAROLA")]
    parola: Option<String>,
    /// Sonucu JSON olarak yaz.
    #[arg(long)]
    json: bool,
}

impl OrtakSecenekler {
    /// Parolayı seçilen kaynaktan okur; hiçbir kaynak yoksa hata döner.
    fn parolayi_oku(&self) -> Result<Vec<u8>, Hata> {
        if let Some(deger) = &self.parola {
            return Ok(deger.as_bytes().to_vec());
        }
        if let Some(dosya) = &self.parola_dosyasi {
            return Ok(satir_sonu_kaldir(&std::fs::read(dosya)?));
        }
        if let Some(ad) = &self.parola_degiskeni {
            return std::env::var(ad)
                .map(String::into_bytes)
                .map_err(|_| Hata::BozukArguman(format!("'{ad}' ortam degiskeni tanimli degil")));
        }
        if self.parola_stdin {
            let mut bayt = Vec::new();
            std::io::stdin().read_to_end(&mut bayt)?;
            return Ok(satir_sonu_kaldir(&bayt));
        }
        if let Ok(deger) = std::env::var(PAROLA_DEGISKENI) {
            return Ok(deger.into_bytes());
        }
        Err(Hata::BozukArguman(format!(
            "parola verilmedi; --parola, --parola-dosyasi, --parola-stdin ya da {PAROLA_DEGISKENI} kullanin"
        )))
    }
}

#[derive(Debug, Args)]
struct SifrelemeSecenekleri {
    /// Parca boyutu (bayt); 524288..8388608.
    #[arg(long, value_name = "BAYT")]
    parca_baytu: Option<u32>,
    /// Argon2id bellek maliyeti (KiB); 16384..262144.
    #[arg(long, value_name = "KIB")]
    argon2_bellek_kib: Option<u32>,
    /// Argon2id tur sayisi; 1..10.
    #[arg(long, value_name = "N")]
    argon2_tur: Option<u32>,
    /// Argon2id yol sayisi; 1..16.
    #[arg(long, value_name = "N")]
    argon2_yol: Option<u32>,
    /// Var olan kapsule uzerine yazilsin mi.
    #[arg(long)]
    ustune_yaz: bool,
    /// Yarim kalmis gecici dosyadan kaldigi yerden devam edilsin mi.
    #[arg(long)]
    devam: bool,
}

impl SifrelemeSecenekleri {
    fn parca_boyutunu(&self) -> Result<u32, Hata> {
        let deger = self.parca_baytu.unwrap_or(VARSAYILAN_PARCA);
        if !(EN_KUCUK_PARCA..=EN_BUYUK_PARCA).contains(&deger) {
            return Err(Hata::BozukArguman(format!(
                "--parca-baytu {deger}; izinli aralik {EN_KUCUK_PARCA}..{EN_BUYUK_PARCA}"
            )));
        }
        Ok(deger)
    }

    fn argon2(&self) -> Argon2Ayar {
        let varsayilan = Argon2Ayar::default();
        Argon2Ayar {
            bellek_kib: self.argon2_bellek_kib.unwrap_or(varsayilan.bellek_kib),
            tur: self.argon2_tur.unwrap_or(varsayilan.tur),
            yol: self.argon2_yol.unwrap_or(varsayilan.yol),
        }
    }
}

fn satir_sonu_kaldir(bayt: &[u8]) -> Vec<u8> {
    let mut son = bayt.len();
    while son > 0 && (bayt[son - 1] == b'\n' || bayt[son - 1] == b'\r') {
        son -= 1;
    }
    bayt[..son].to_vec()
}

#[derive(Serialize)]
struct SifreleCiktisi {
    islem: &'static str,
    kapsul: String,
    kaynak: String,
    dosya_sayisi: u64,
    dizin_sayisi: u64,
    parca_sayisi: u64,
    girdi_bayti: u64,
    kapsul_bayti: u64,
    devam_edildi: bool,
    etik_dogrulama: &'static str,
    sure_ms: u128,
}

#[derive(Serialize)]
struct AcCiktisi {
    islem: &'static str,
    hedef: String,
    dosya_sayisi: u64,
    dizin_sayisi: u64,
    parca_sayisi: u64,
    cikti_bayti: u64,
    kuyruk_ozeti_dogrulandi: bool,
    izin_uygulanamadi: u64,
    etik_dogrulama: &'static str,
    sure_ms: u128,
}

#[derive(Serialize)]
struct BilgiCiktisi {
    islem: &'static str,
    kapsul: String,
    bicim_surumu: u8,
    parca_boyutu: u32,
    argon2_bellek_kib: u32,
    argon2_tur: u32,
    argon2_yol: u32,
    dizin_agaci: bool,
    kok_ad: String,
    girdi_sayisi: u64,
    parca_sayisi: u64,
    girdi_bayti: u64,
    kapsul_bayti: u64,
    etik_yuku_yuzdesi: f64,
    kuyruk_ozeti_dogrulandi: bool,
}

#[derive(Serialize)]
struct DogrulaCiktisi {
    islem: &'static str,
    kapsul: String,
    dogrulanan_parca: u64,
    dogrulanan_bayt: u64,
    dosya_sayisi: u64,
    kuyruk_ozeti_dogrulandi: bool,
    sonuc: &'static str,
    sure_ms: u128,
}

fn main() -> ExitCode {
    let komut = KomutSatiri::parse();
    match calistir(komut) {
        Ok(()) => ExitCode::SUCCESS,
        Err(hata) => {
            eprintln!("mseal: {hata}");
            ExitCode::FAILURE
        }
    }
}

fn calistir(komut: KomutSatiri) -> Result<(), Hata> {
    match komut.alt_komut {
        AltKomut::Sifrele {
            kaynak,
            kapsul,
            sifreleme,
            ortak,
        } => sifrele(&kaynak, &kapsul, &sifreleme, &ortak),
        AltKomut::Ac {
            kapsul,
            hedef,
            ustune_yaz,
            kuyruk_ozeti_atla,
            ortak,
        } => ac(&kapsul, &hedef, &ortak, ustune_yaz, !kuyruk_ozeti_atla),
        AltKomut::Listele { kapsul, ortak } | AltKomut::Bilgi { kapsul, ortak } => {
            listele(&kapsul, &ortak)
        }
        AltKomut::Dogrula { kapsul, ortak } => dogrula(&kapsul, &ortak),
    }
}

fn sifrele(
    kaynak: &Path,
    kapsul: &Path,
    secenek: &SifrelemeSecenekleri,
    ortak: &OrtakSecenekler,
) -> Result<(), Hata> {
    let parola = ortak.parolayi_oku()?;
    let ayarlar = MuhurSecenekleri {
        parca_boyutu: secenek.parca_boyutunu()?,
        argon2: secenek.argon2(),
        ustune_yaz: secenek.ustune_yaz,
        devam: secenek.devam,
        ilerleme: ilerleme_yazici(),
    };
    let rapor = akis::muhurle(kaynak, kapsul, &parola, &ayarlar)?;
    if ortak.json {
        yaz_json(&SifreleCiktisi {
            islem: "mseal sifrele",
            kapsul: rapor.kapsul.display().to_string(),
            kaynak: rapor.kaynak.display().to_string(),
            dosya_sayisi: rapor.dosya_sayisi,
            dizin_sayisi: rapor.dizin_sayisi,
            parca_sayisi: rapor.parca_sayisi,
            girdi_bayti: rapor.girdi_bayti,
            kapsul_bayti: rapor.kapsul_bayti,
            devam_edildi: rapor.devam_edildi,
            etik_dogrulama: "tamam",
            sure_ms: rapor.sure_ms,
        })?;
    } else {
        println!("Kapsul yazildi : {}", rapor.kapsul.display());
        println!("Dosya          : {}", rapor.dosya_sayisi);
        println!("Dizin          : {}", rapor.dizin_sayisi);
        println!("Parca          : {}", rapor.parca_sayisi);
        println!(
            "Girdi          : {} bayt -> kapsul {} bayt",
            rapor.girdi_bayti, rapor.kapsul_bayti
        );
        println!("Sure           : {} ms", rapor.sure_ms);
    }
    Ok(())
}

fn ac(
    kapsul: &Path,
    hedef: &Path,
    ortak: &OrtakSecenekler,
    ustune_yaz: bool,
    kuyruk_ozeti: bool,
) -> Result<(), Hata> {
    let parola = ortak.parolayi_oku()?;
    let ayarlar = AcSecenekleri {
        ustune_yaz,
        kuyruk_ozetini_dogrula: kuyruk_ozeti,
        ilerleme: ilerleme_yazici(),
    };
    let rapor = akis::ac(kapsul, hedef, &parola, &ayarlar)?;
    if ortak.json {
        yaz_json(&AcCiktisi {
            islem: "mseal ac",
            hedef: rapor.hedef.display().to_string(),
            dosya_sayisi: rapor.dosya_sayisi,
            dizin_sayisi: rapor.dizin_sayisi,
            parca_sayisi: rapor.parca_sayisi,
            cikti_bayti: rapor.cikti_bayti,
            kuyruk_ozeti_dogrulandi: rapor.kuyruk_ozeti_dogrulandi,
            izin_uygulanamadi: rapor.izin_uygulanamadi,
            etik_dogrulama: "tamam",
            sure_ms: rapor.sure_ms,
        })?;
    } else {
        println!("Geri yuklendi  : {}", rapor.hedef.display());
        println!("Dosya          : {}", rapor.dosya_sayisi);
        println!("Dizin          : {}", rapor.dizin_sayisi);
        println!("Parca          : {}", rapor.parca_sayisi);
        println!("Cikti          : {} bayt", rapor.cikti_bayti);
        println!("Sure           : {} ms", rapor.sure_ms);
    }
    Ok(())
}

fn listele(kapsul: &Path, ortak: &OrtakSecenekler) -> Result<(), Hata> {
    let parola = ortak.parolayi_oku()?;
    let ozet = akis::kapsul_ozeti_oku(kapsul, &parola)?;
    if ortak.json {
        yaz_json(&BilgiCiktisi {
            islem: "mseal listele",
            kapsul: kapsul.display().to_string(),
            bicim_surumu: ozet.surum,
            parca_boyutu: ozet.parca_boyutu,
            argon2_bellek_kib: ozet.argon2.bellek_kib,
            argon2_tur: ozet.argon2.tur,
            argon2_yol: ozet.argon2.yol,
            dizin_agaci: ozet.dizin_agaci,
            kok_ad: ozet.kok_ad,
            girdi_sayisi: ozet.girdi_sayisi,
            parca_sayisi: ozet.parca_sayisi,
            girdi_bayti: ozet.girdi_bayti,
            kapsul_bayti: ozet.kapsul_bayti,
            etik_yuku_yuzdesi: ozet.etik_yuku_yuzdesi,
            kuyruk_ozeti_dogrulandi: ozet.kuyruk_ozeti_dogrulandi,
        })?;
    } else {
        println!("Kapsul         : {}", kapsul.display());
        println!(
            "Kok dizin      : {} ({} )",
            ozet.kok_ad,
            if ozet.dizin_agaci {
                "klasor agaci"
            } else {
                "tek dosya"
            }
        );
        println!(
            "Argon2id       : {} KiB / {} tur / {} yol",
            ozet.argon2.bellek_kib, ozet.argon2.tur, ozet.argon2.yol
        );
        println!(
            "Parca          : {} bayt, {} parca, {} girdi",
            ozet.parca_boyutu, ozet.parca_sayisi, ozet.girdi_sayisi
        );
        println!("Girdi          : {} bayt", ozet.girdi_bayti);
        println!("Kapsul         : {} bayt", ozet.kapsul_bayti);
        println!("Etik yuku      : %{:.4}", ozet.etik_yuku_yuzdesi);
    }
    Ok(())
}

fn dogrula(kapsul: &Path, ortak: &OrtakSecenekler) -> Result<(), Hata> {
    let parola = ortak.parolayi_oku()?;
    let rapor = sealedbox::dogrulama::dogrula(kapsul, &parola)?;
    if ortak.json {
        yaz_json(&DogrulaCiktisi {
            islem: "mseal-verify",
            kapsul: rapor.kapsul,
            dogrulanan_parca: rapor.dogrulanan_parca,
            dogrulanan_bayt: rapor.dogrulanan_bayt,
            dosya_sayisi: rapor.dosya_sayisi,
            kuyruk_ozeti_dogrulandi: rapor.kuyruk_ozeti_dogrulandi,
            sonuc: "tamam",
            sure_ms: rapor.sure_ms,
        })?;
    } else {
        println!("Kapsul         : {}", rapor.kapsul);
        println!(
            "Dogrulanan     : {} parca / {} bayt",
            rapor.dogrulanan_parca, rapor.dogrulanan_bayt
        );
        println!("Sonuc          : {}", rapor.sonuc);
        println!("Sure           : {} ms", rapor.sure_ms);
    }
    Ok(())
}

fn yaz_json<T: Serialize>(veri: &T) -> Result<(), Hata> {
    let metin = serde_json::to_string_pretty(veri)
        .map_err(|hata| Hata::BozukArguman(format!("JSON uretilemedi: {hata}")))?;
    let mut cikti = std::io::stdout().lock();
    writeln!(cikti, "{metin}")?;
    cikti.flush()?;
    Ok(())
}

fn ilerleme_yazici() -> Option<IlerlemeGeriCagri> {
    None
}
