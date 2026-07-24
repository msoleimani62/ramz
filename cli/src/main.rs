use std::fs;
use std::io::Read;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};

use ramz_backend_7z::SevenZBackend;
use ramz_backends_age::AgeBackend;
use ramz_core::{
    read_and_confirm_password, safe_output_dir, Backend, DryRunReport, PackOptions,
    ProgressReporter, RamzError, Result, Target,
};

// Main CLI structure
// ساختار اصلی CLI
#[derive(Parser)]
#[command(name = "ramz")]
#[command(about = "Secure file archiver with age and 7z backends")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

// CLI subcommands
// ساب‌کامندهای CLI
#[derive(Subcommand)]
enum Commands {
    #[command(about = "Pack files into an encrypted archive")]
    Pack {
        #[arg(help = "Source file or directory to archive")]
        source: PathBuf,

        #[arg(short, long, help = "Output directory for the archive")]
        output: Option<PathBuf>,

        #[arg(short, long, help = "Password for encryption")]
        password: Option<String>,

        #[arg(short, long, help = "Confirm password interactively")]
        confirm_password: bool,

        #[arg(
            short = 'l',
            long,
            help = "Compression level (1-22 for age, 0-9 for 7z)"
        )]
        compression_level: Option<u8>,

        #[arg(short, long, help = "Delete source after successful verification")]
        delete_source: bool,

        #[arg(
            long,
            help = "Securely overwrite source before deletion (slower, more secure)"
        )]
        secure_delete: bool,

        #[arg(short, long, help = "Force overwrite existing archive")]
        force: bool,

        #[arg(
            short,
            long,
            help = "Backend to use",
            value_enum,
            default_value = "age"
        )]
        backend: BackendChoice,

        #[arg(long, help = "Use Argon2id instead of default KDF")]
        argon2id: bool,

        #[arg(long, help = "Enable post-quantum ML-KEM hybrid encryption")]
        mlkem: bool,

        #[arg(
            long,
            help = "Encrypt for a recipient identity (no password needed for pack)"
        )]
        recipient: Option<PathBuf>,

        #[arg(long, help = "Preview output without creating archive")]
        dry_run: bool,

        #[arg(long, help = "Resume interrupted archive")]
        resume: bool,

        #[arg(
            long,
            help = "Argon2 memory in KiB (default: 65536)",
            default_value = "65536"
        )]
        argon2_memory_kib: u32,

        #[arg(long, help = "Argon2 iterations (default: 3)", default_value = "3")]
        argon2_iterations: u32,

        #[arg(long, help = "Argon2 parallelism (default: 4)", default_value = "4")]
        argon2_parallelism: u32,
    },

    #[command(about = "Verify archive integrity")]
    Verify {
        #[arg(help = "Archive file to verify")]
        archive: PathBuf,

        #[arg(short, long, help = "Password for decryption")]
        password: Option<String>,

        #[arg(long, help = "Identity file for recipient-based archive verification")]
        identity: Option<PathBuf>,
    },

    #[command(about = "Extract archive contents")]
    Extract {
        #[arg(help = "Archive file to extract")]
        archive: PathBuf,

        #[arg(short, long, help = "Output directory")]
        output: Option<PathBuf>,

        #[arg(short, long, help = "Password for decryption")]
        password: Option<String>,

        #[arg(long, help = "Identity file for recipient-based decryption")]
        identity: Option<PathBuf>,
    },

    #[command(about = "Generate a new ML-KEM identity for recipient-based encryption")]
    Keygen {
        #[arg(short, long, help = "Output directory for identity files")]
        output: Option<PathBuf>,

        #[arg(short, long, help = "Protect secret key with a password")]
        password: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, ValueEnum)]
enum BackendChoice {
    Age,
    SevenZ,
}

// CLI progress bar implementation
// پیاده‌سازی نوار پیشرفت CLI
struct CliProgress {
    bar: ProgressBar,
}

impl CliProgress {
    fn new() -> Self {
        let bar = ProgressBar::new(0);
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );
        Self { bar }
    }
}

impl ProgressReporter for CliProgress {
    fn set_total(&mut self, total_bytes: u64) {
        self.bar.set_length(total_bytes);
    }

    fn on_progress(&mut self, processed_bytes: u64) {
        self.bar.set_position(processed_bytes);
    }

    fn finish(&mut self, message: &str) {
        self.bar.finish_with_message(message.to_string());
    }
}

// Prompt for password with optional confirmation
// درخواست پسورد با تایید اختیاری
fn get_password(confirm: bool) -> Result<String> {
    if confirm {
        println!("Enter password:");
        let p1 = rpassword::read_password().map_err(RamzError::Io)?;
        println!("Confirm password:");
        let p2 = rpassword::read_password().map_err(RamzError::Io)?;
        read_and_confirm_password(|| Ok(p1), || Ok(p2))
    } else {
        println!("Enter password:");
        let pw = rpassword::read_password().map_err(RamzError::Io)?;
        if pw.is_empty() {
            return Err(RamzError::EmptyPassword);
        }
        Ok(pw)
    }
}

// Print dry-run estimation report
// چاپ گزارش تخمین dry-run
fn print_dry_run_report(report: &DryRunReport) {
    println!("\n╔══════════════════════════════════════════════╗");
    println!("║          DRY RUN PREVIEW                       ║");
    println!("╠══════════════════════════════════════════════╣");
    println!("║ Source:        {:<45} ║", report.source_path.display());
    println!(
        "║ Type:          {:<45} ║",
        format!("{:?}", report.source_kind)
    );
    println!(
        "║ Source size:   {:<45} ║",
        ramz_core::dry_run::format_size(report.source_size)
    );
    println!(
        "║ Estimated:     {:<45} ║",
        ramz_core::dry_run::format_size(report.estimated_archive_size)
    );
    println!(
        "║ Ratio:         {:<45} ║",
        format!("{:.1}%", report.compression_ratio * 100.0)
    );
    println!("║ Output:        {:<45} ║", report.output_path.display());
    println!("║ Backend:       {:<45} ║", report.backend_name);
    println!(
        "║ Password:      {:<45} ║",
        if report.password_protected {
            "Yes"
        } else {
            "No"
        }
    );
    println!(
        "║ Delete source: {:<45} ║",
        if report.will_delete_source {
            "Yes"
        } else {
            "No"
        }
    );
    println!(
        "║ Secure delete: {:<45} ║",
        if report.will_secure_delete {
            "Yes"
        } else {
            "No"
        }
    );
    println!("╠══════════════════════════════════════════════╣");
    println!(
        "║ Already compressed files (will be stored): {:<3}     ║",
        report.already_compressed_files.len()
    );
    for f in &report.already_compressed_files {
        println!(
            "║   • {}",
            f.file_name().unwrap_or_default().to_string_lossy()
        );
    }
    println!(
        "║ Compressible files: {:<3}      ║",
        report.compressible_files.len()
    );
    println!("╚══════════════════════════════════════════════╝\n");
}

// Main CLI execution logic
// منطق اجرای اصلی CLI
fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Pack {
            source,
            output,
            password,
            confirm_password,
            compression_level,
            delete_source,
            secure_delete,
            force,
            backend,
            argon2id,
            mlkem,
            recipient,
            dry_run,
            resume,
            argon2_memory_kib,
            argon2_iterations,
            argon2_parallelism,
        } => {
            if backend == BackendChoice::SevenZ && (argon2id || mlkem) {
                return Err(RamzError::IncompatibleFlag(
                    "--argon2id/--mlkem only supported with --backend age".into(),
                )
                .into());
            }

            if backend == BackendChoice::SevenZ && recipient.is_some() {
                return Err(RamzError::IncompatibleFlag(
                    "--recipient only supported with --backend age".into(),
                )
                .into());
            }

            let target = Target::detect(&source)?;

            let password = match (password, recipient.is_some()) {
                (Some(p), false) => {
                    if confirm_password {
                        println!("Confirm password:");
                        let p2 = rpassword::read_password()?;
                        read_and_confirm_password(|| Ok(p), || Ok(p2))?
                    } else {
                        if p.is_empty() {
                            return Err(RamzError::EmptyPassword.into());
                        }
                        p
                    }
                }
                (None, false) => get_password(confirm_password)?,
                (Some(_), true) => {
                    return Err(RamzError::IncompatibleFlag(
                        "--password cannot be used with --recipient (recipient archives use identity-based decryption, not passwords)".into(),
                    )
                    .into());
                }
                (None, true) => String::new(),
            };

            let output_dir = safe_output_dir(&source, output.as_deref());
            fs::create_dir_all(&output_dir)?;

            let extension = match backend {
                BackendChoice::Age => AgeBackend::new().extension(),
                BackendChoice::SevenZ => SevenZBackend.extension(),
            };

            let archive_name = format!(
                "{}.{}",
                source.file_stem().unwrap_or_default().to_string_lossy(),
                extension
            );
            let archive_path = output_dir.join(&archive_name);

            if resume && ramz_core::resume::is_resumable(&archive_path) {
                if let Some(state) = ramz_core::resume::load_resume_state(&archive_path)? {
                    // چک‌سام رو مستقیم مقایسه می‌کنیم، نه از طریق verify_source_unchanged
                    // که چک‌سام و processed_bytes==total_bytes رو با هم قاطی می‌کنه و
                    // نمی‌شه فرق «سورس عوض شده» رو از «pack ناتمومه» تشخیص داد
                    // compare the checksum directly instead of relying only on
                    // verify_source_unchanged, which conflates checksum mismatch with
                    // an incomplete pack and can't distinguish "source changed" from
                    // "previous attempt was just unfinished"
                    let current_checksum = ramz_core::resume::compute_file_checksum(&source)?;
                    let source_unchanged = current_checksum == state.checksum;

                    if !source_unchanged {
                        return Err(RamzError::ResumeMismatch(
                            "source has changed since last run; cannot resume".into(),
                        )
                        .into());
                    }

                    // فقط چک‌سام یکسان بودن کافی نیست؛ باید مطمئن بشیم پک قبلی
                    // واقعاً کامل شده (processed_bytes == total_bytes) و آرشیو
                    // واقعاً روی دیسک وجود داره - وگرنه یه تلاش قطع‌شده رو به
                    // اشتباه "کامل" اعلام می‌کنیم
                    // matching checksum alone is not enough; we must also confirm
                    // the previous attempt actually finished (processed_bytes ==
                    // total_bytes) and the archive file genuinely exists on disk -
                    // otherwise an interrupted attempt gets wrongly reported as complete
                    let archive_actually_complete =
                        state.processed_bytes == state.total_bytes && archive_path.exists();

                    if archive_actually_complete {
                        println!(
                            "Resume: source unchanged since last run. Archive already complete."
                        );
                        return Ok(());
                    }

                    println!("Resume: previous attempt was incomplete; re-creating archive...");
                }
            }

            if archive_path.exists() && !force && !resume {
                return Err(RamzError::ArchiveExists(archive_path).into());
            }

            let level = compression_level.unwrap_or(match backend {
                BackendChoice::Age => 9,
                BackendChoice::SevenZ => 5,
            });

            let opts = PackOptions {
                password: if recipient.is_some() {
                    None
                } else {
                    Some(password)
                },
                compression_level: level,
                delete_source,
                output_dir: Some(output_dir),
                force_overwrite: force,
                argon2_memory_kib,
                argon2_iterations,
                argon2_parallelism,
                secure_delete,
            };

            if dry_run {
                let report = ramz_core::dry_run::estimate_archive_size(
                    &target,
                    &opts,
                    match backend {
                        BackendChoice::Age => "age",
                        BackendChoice::SevenZ => "7z",
                    },
                )?;
                print_dry_run_report(&report);
                return Ok(());
            }

            let checksum = ramz_core::resume::compute_file_checksum(&source)?;
            let resume_state = ramz_core::resume::ResumeState {
                source_path: source.clone(),
                archive_path: archive_path.clone(),
                backend_name: match backend {
                    BackendChoice::Age => "age".to_string(),
                    BackendChoice::SevenZ => "7z".to_string(),
                },
                total_bytes: target.total_bytes,
                processed_bytes: 0,
                checksum,
                password_hint: None,
                created_at: format!("{:?}", std::time::SystemTime::now()),
            };
            ramz_core::resume::save_resume_state(&resume_state, &archive_path)?;

            let mut progress = CliProgress::new();

            let backend: Box<dyn Backend> = match backend {
                BackendChoice::Age => {
                    let age_backend = if let Some(recipient_path) = recipient {
                        let mut pub_file = fs::File::open(&recipient_path)?;
                        let mut pub_raw = Vec::new();
                        pub_file.read_to_end(&mut pub_raw)?;
                        if !pub_raw.starts_with(b"RIM1PUB") {
                            return Err(RamzError::Backend(
                                "invalid recipient file (expected RIM1PUB identity)".into(),
                            )
                            .into());
                        }
                        let mut pos = 7usize;
                        let ek_len =
                            u32::from_le_bytes(pub_raw[pos..pos + 4].try_into().unwrap()) as usize;
                        pos += 4;
                        let ek = pub_raw[pos..pos + ek_len].to_vec();
                        AgeBackend::new_with_recipient(ek)
                    } else if mlkem {
                        AgeBackend::new_with_mlkem()
                    } else if argon2id {
                        AgeBackend::new_with_argon2id()
                    } else {
                        AgeBackend::new()
                    };
                    Box::new(age_backend)
                }
                BackendChoice::SevenZ => Box::new(SevenZBackend),
            };

            backend.pack(&target, &archive_path, &opts, &mut progress)?;

            let mut completed_state = resume_state;
            completed_state.processed_bytes = target.total_bytes;
            ramz_core::resume::save_resume_state(&completed_state, &archive_path)?;

            if delete_source {
                println!("Verifying archive integrity before deleting source...");
                backend.verify(&archive_path, opts.password.as_deref())?;
                println!("Verification passed. Deleting source...");

                if secure_delete {
                    println!("Using secure deletion (overwrite + remove)...");
                }

                ramz_core::secure_delete::delete_path(&source, secure_delete)?;
            }

            ramz_core::resume::remove_resume_state(&archive_path)?;

            println!("Archive created: {}", archive_path.display());
        }

        Commands::Verify {
            archive,
            password,
            identity,
        } => {
            let backend: Box<dyn Backend> =
                if archive.extension().map(|e| e == "7z").unwrap_or(false) {
                    Box::new(SevenZBackend)
                } else {
                    Box::new(AgeBackend::new())
                };

            if let Some(id_path) = identity {
                let age_backend = AgeBackend::new();
                // به‌جای leak کردن حافظه، پسورد وارد‌شده رو توی یه متغیر بیرونی
                // نگه می‌داریم تا عمرش کافی باشه و در پایان اسکوپ به‌طور طبیعی آزاد بشه
                // instead of leaking memory, keep the entered password in an
                // outer-scope variable so its lifetime is sufficient and it gets
                // freed normally at the end of scope
                //
                // اینجا مستقیم از خودِ password (نه یه پرامپت عمومی جدا) استفاده
                // می‌کنیم - چون archive identity-based هست، پرسیدن یه پسورد عمومی
                // قبل از این گیج‌کننده‌ست؛ فقط اگه واقعاً برای رمزگشایی خودِ
                // identity لازم باشه می‌پرسیم
                // we use `password` directly here (not a separate generic prompt)
                // - since this is an identity-based archive, asking for a generic
                // password first would be confusing; we only prompt if the
                // identity itself actually needs one to decrypt
                let entered_password;
                let id_pw: Option<&str> =
                    if password.as_ref().map(|p| !p.is_empty()).unwrap_or(false) {
                        password.as_deref()
                    } else {
                        println!("Enter identity password (or press Enter if none):");
                        entered_password = rpassword::read_password()?;
                        if entered_password.is_empty() {
                            None
                        } else {
                            Some(entered_password.as_str())
                        }
                    };
                let identity = ramz_backends_age::identity::Identity::load_with_password(
                    &id_path.with_extension("pub"),
                    &id_path,
                    id_pw.unwrap_or(""),
                )?;
                age_backend.verify_with_identity(&archive, &identity)?;
            } else {
                let pw = match password {
                    Some(p) => Some(p),
                    None => {
                        println!("Enter password:");
                        let p = rpassword::read_password()?;
                        Some(p)
                    }
                };
                backend.verify(&archive, pw.as_deref())?;
            }
            println!("Archive verification passed.");
        }

        Commands::Extract {
            archive,
            output,
            password,
            identity,
        } => {
            let extract_dir =
                output.unwrap_or_else(|| archive.file_stem().unwrap_or_default().into());
            fs::create_dir_all(&extract_dir)?;

            let backend: Box<dyn Backend> =
                if archive.extension().map(|e| e == "7z").unwrap_or(false) {
                    Box::new(SevenZBackend)
                } else {
                    Box::new(AgeBackend::new())
                };

            if let Some(id_path) = identity {
                let age_backend = AgeBackend::new();
                // همون الگوی جلوگیری از نشت حافظه که توی Verify استفاده کردیم
                // the same memory-leak-avoidance pattern used in Verify
                let entered_password;
                let id_pw: Option<&str> =
                    if password.as_ref().map(|p| !p.is_empty()).unwrap_or(false) {
                        password.as_deref()
                    } else {
                        println!("Enter identity password (or press Enter if none):");
                        entered_password = rpassword::read_password()?;
                        if entered_password.is_empty() {
                            None
                        } else {
                            Some(entered_password.as_str())
                        }
                    };
                let identity = ramz_backends_age::identity::Identity::load_with_password(
                    &id_path.with_extension("pub"),
                    &id_path,
                    id_pw.unwrap_or(""),
                )?;
                age_backend.extract_to_dir(
                    &archive,
                    &extract_dir,
                    password.as_deref(),
                    Some(&identity),
                )?;
            } else {
                // مثل pack و verify، اگه پسوردی داده نشده باشه تعاملی بپرس -
                // قبلاً اینجا مستقیم None پاس می‌شد و کاربر فقط با خطای
                // «age requires a password» مواجه می‌شد، بدون فرصت وارد کردن
                // like pack and verify, prompt interactively if no password was
                // given - this used to pass None straight through and the user
                // just hit an "age requires a password" error with no chance
                // to enter one
                let pw = match password {
                    Some(p) => Some(p),
                    None => {
                        println!("Enter password:");
                        let p = rpassword::read_password()?;
                        Some(p)
                    }
                };
                backend.extract(&archive, &extract_dir, pw.as_deref())?;
            }

            println!("Extracted to: {}", extract_dir.display());
        }

        Commands::Keygen { output, password } => {
            let output_dir = output.unwrap_or_else(|| {
                dirs::home_dir()
                    .map(|h| h.join(".config").join("ramz"))
                    .unwrap_or_else(|| PathBuf::from("."))
            });
            fs::create_dir_all(&output_dir)?;

            let pub_path = output_dir.join("identity.pub");
            let sec_path = output_dir.join("identity");

            if pub_path.exists() || sec_path.exists() {
                return Err(RamzError::ArchiveExists(
                    "identity files already exist; use --output to specify a different directory"
                        .into(),
                )
                .into());
            }

            println!("Generating ML-KEM-768 identity...");
            let identity = ramz_backends_age::identity::Identity::generate();

            let pw = if password {
                println!("Enter password to protect identity:");
                let p1 = rpassword::read_password()?;
                println!("Confirm password:");
                let p2 = rpassword::read_password()?;
                if p1 != p2 {
                    return Err(RamzError::PasswordMismatch.into());
                }
                if p1.is_empty() {
                    return Err(RamzError::EmptyPassword.into());
                }
                Some(p1)
            } else {
                println!("No password protection (storage-only encryption).");
                None
            };

            identity.save(&pub_path, &sec_path, pw.as_deref())?;

            println!("Identity created:");
            println!("  Public:  {}", pub_path.display());
            println!("  Secret:  {}", sec_path.display());
            println!(
                "  Encapsulation key: {} bytes",
                identity.encapsulation_key.len()
            );
            println!(
                "  Decapsulation key: {} bytes",
                identity.decapsulation_key.len()
            );
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem_rejected_for_7z_backend() {
        let result = run(Cli {
            command: Commands::Pack {
                source: PathBuf::from("."),
                output: None,
                password: None,
                confirm_password: false,
                compression_level: None,
                delete_source: false,
                secure_delete: false,
                force: false,
                backend: BackendChoice::SevenZ,
                argon2id: false,
                mlkem: true,
                recipient: None,
                dry_run: false,
                resume: false,
                argon2_memory_kib: 65536,
                argon2_iterations: 3,
                argon2_parallelism: 4,
            },
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_recipient_rejected_for_7z_backend() {
        let result = run(Cli {
            command: Commands::Pack {
                source: PathBuf::from("."),
                output: None,
                password: None,
                confirm_password: false,
                compression_level: None,
                delete_source: false,
                secure_delete: false,
                force: false,
                backend: BackendChoice::SevenZ,
                argon2id: false,
                mlkem: false,
                recipient: Some(PathBuf::from("identity.pub")),
                dry_run: false,
                resume: false,
                argon2_memory_kib: 65536,
                argon2_iterations: 3,
                argon2_parallelism: 4,
            },
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_password_rejected_with_recipient() {
        let result = run(Cli {
            command: Commands::Pack {
                source: PathBuf::from("."),
                output: None,
                password: Some("password".to_string()),
                confirm_password: false,
                compression_level: None,
                delete_source: false,
                secure_delete: false,
                force: false,
                backend: BackendChoice::Age,
                argon2id: false,
                mlkem: false,
                recipient: Some(PathBuf::from("identity.pub")),
                dry_run: false,
                resume: false,
                argon2_memory_kib: 65536,
                argon2_iterations: 3,
                argon2_parallelism: 4,
            },
        });
        assert!(result.is_err());
    }

    // این تست دقیقاً همون باگی رو بازآفرینی می‌کنه که پیدا و رفع کردیم:
    // resume قبلاً فقط چک‌سام سورس رو چک می‌کرد، نه این‌که آرشیو واقعاً
    // ساخته شده یا نه. اگه یه pack وسط کار قطع بشه (سورس دست‌نخورده،
    // آرشیو هنوز ساخته نشده)، نسخه‌ی قدیمی پیام «Archive already
    // complete» می‌داد بدون این‌که واقعاً چیزی بسازه - این تست تضمین
    // می‌کنه که این اتفاق دیگه نمی‌افته
    // this test reproduces the exact bug we found and fixed: resume used
    // to only check the source checksum, never whether the archive was
    // actually created. if a pack got interrupted (source untouched,
    // archive never written), the old code printed "Archive already
    // complete" without creating anything - this test guarantees that
    // can't happen again
    #[test]
    fn test_resume_does_not_falsely_report_completion() {
        let tmp = tempfile::TempDir::new().unwrap();
        let source = tmp.path().join("data.txt");
        std::fs::write(&source, b"some content for resume test").unwrap();

        let archive_path = tmp.path().join("data.age.tar.zst");
        let checksum = ramz_core::resume::compute_file_checksum(&source).unwrap();

        // شبیه‌سازی وضعیت "قطع‌شده": resume state با processed_bytes=0 ذخیره
        // شده ولی هیچ آرشیوی روی دیسک وجود نداره
        // simulate an "interrupted" state: resume state saved with
        // processed_bytes=0, but no archive file exists on disk
        let interrupted_state = ramz_core::resume::ResumeState {
            source_path: source.clone(),
            archive_path: archive_path.clone(),
            backend_name: "age".to_string(),
            total_bytes: 29,
            processed_bytes: 0,
            checksum,
            password_hint: None,
            created_at: "2026-01-01".to_string(),
        };
        ramz_core::resume::save_resume_state(&interrupted_state, &archive_path).unwrap();

        assert!(
            !archive_path.exists(),
            "precondition: archive must not exist yet"
        );

        let cli = Cli {
            command: Commands::Pack {
                source: source.clone(),
                output: Some(tmp.path().to_path_buf()),
                password: Some("test-password".to_string()),
                confirm_password: false,
                compression_level: None,
                delete_source: false,
                secure_delete: false,
                force: false,
                backend: BackendChoice::Age,
                argon2id: false,
                mlkem: false,
                recipient: None,
                dry_run: false,
                resume: true,
                argon2_memory_kib: 65536,
                argon2_iterations: 3,
                argon2_parallelism: 4,
            },
        };

        run(cli).unwrap();

        assert!(
            archive_path.exists(),
            "BUG: resume declared the archive complete without actually creating it"
        );

        let backend = AgeBackend::new();
        backend
            .verify(&archive_path, Some("test-password"))
            .unwrap();
    }
}
