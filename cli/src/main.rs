use std::fs;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};

use ramz_backend_7z::SevenZBackend;
use ramz_backends_age::AgeBackend;
use ramz_core::{
    read_and_confirm_password, safe_output_dir, Backend, DryRunReport, PackOptions,
    ProgressReporter, RamzError, Result, Target,
};

#[derive(Parser)]
#[command(name = "ramz")]
#[command(about = "Secure file archiver with age and 7z backends")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

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
    },

    #[command(about = "Extract archive contents")]
    Extract {
        #[arg(help = "Archive file to extract")]
        archive: PathBuf,

        #[arg(short, long, help = "Output directory")]
        output: Option<PathBuf>,

        #[arg(short, long, help = "Password for decryption")]
        password: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, ValueEnum)]
enum BackendChoice {
    Age,
    SevenZ,
}

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

fn print_dry_run_report(report: &DryRunReport) {
    println!("\n╔══════════════════════════════════════════════════╗");
    println!("║          DRY RUN PREVIEW                             ║");
    println!("╠══════════════════════════════════════════════════╣");
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
    println!("╠══════════════════════════════════════════════════╣");
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
    println!("╚══════════════════════════════════════════════════╝\n");
}

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

            let target = Target::detect(&source)?;

            let password = match password {
                Some(p) => {
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
                None => get_password(confirm_password)?,
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
                    let source_unchanged = ramz_core::resume::verify_source_unchanged(&state)?;

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
                password: Some(password),
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

            match backend {
                BackendChoice::Age => {
                    let backend = if mlkem {
                        AgeBackend::new_with_mlkem()
                    } else if argon2id {
                        AgeBackend::new_with_argon2id()
                    } else {
                        AgeBackend::new()
                    };
                    backend.pack(&target, &archive_path, &opts, &mut progress)?;
                }
                BackendChoice::SevenZ => {
                    let backend = SevenZBackend;
                    backend.pack(&target, &archive_path, &opts, &mut progress)?;
                }
            }

            let mut completed_state = resume_state;
            completed_state.processed_bytes = target.total_bytes;
            ramz_core::resume::save_resume_state(&completed_state, &archive_path)?;

            if delete_source {
                println!("Verifying archive integrity before deleting source...");
                let verify_result = match backend {
                    BackendChoice::Age => {
                        let backend = AgeBackend::new();
                        backend.verify(&archive_path, opts.password.as_deref())
                    }
                    BackendChoice::SevenZ => {
                        let backend = SevenZBackend;
                        backend.verify(&archive_path, opts.password.as_deref())
                    }
                };
                verify_result?;
                println!("Verification passed. Deleting source...");

                if secure_delete {
                    println!("Using secure deletion (overwrite + remove)...");
                }

                ramz_core::secure_delete::delete_path(&source, secure_delete)?;
            }

            ramz_core::resume::remove_resume_state(&archive_path)?;

            println!("Archive created: {}", archive_path.display());
        }

        Commands::Verify { archive, password } => {
            let pw = match password {
                Some(p) => Some(p),
                None => {
                    println!("Enter password:");
                    let p = rpassword::read_password()?;
                    Some(p)
                }
            };

            let backend: Box<dyn Backend> =
                if archive.extension().map(|e| e == "7z").unwrap_or(false) {
                    Box::new(SevenZBackend)
                } else {
                    Box::new(AgeBackend::new())
                };

            backend.verify(&archive, pw.as_deref())?;
            println!("Archive verification passed.");
        }

        Commands::Extract {
            archive,
            output,
            password,
        } => {
            let pw = match password {
                Some(p) => Some(p),
                None => {
                    println!("Enter password:");
                    let p = rpassword::read_password()?;
                    Some(p)
                }
            };

            let extract_dir =
                output.unwrap_or_else(|| archive.file_stem().unwrap_or_default().into());
            fs::create_dir_all(&extract_dir)?;

            if archive.extension().map(|e| e == "7z").unwrap_or(false) {
                let backend = SevenZBackend;
                backend.extract(&archive, &extract_dir, pw.as_deref())?;
            } else {
                let backend = AgeBackend::new();
                backend.extract_to_dir(&archive, &extract_dir, pw.as_deref())?;
            }

            println!("Extracted to: {}", extract_dir.display());
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
        let cli = Cli {
            command: Commands::Pack {
                source: PathBuf::from("/tmp/fake"),
                output: None,
                password: Some("test".to_string()),
                confirm_password: false,
                compression_level: None,
                delete_source: false,
                secure_delete: false,
                force: false,
                backend: BackendChoice::SevenZ,
                argon2id: false,
                mlkem: true,
                dry_run: false,
                resume: false,
                argon2_memory_kib: 65536,
                argon2_iterations: 3,
                argon2_parallelism: 4,
            },
        };
        let result = run(cli);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("--argon2id/--mlkem only supported with --backend age"));
    }

    #[test]
    fn test_argon2id_rejected_for_7z_backend() {
        let cli = Cli {
            command: Commands::Pack {
                source: PathBuf::from("/tmp/fake"),
                output: None,
                password: Some("test".to_string()),
                confirm_password: false,
                compression_level: None,
                delete_source: false,
                secure_delete: false,
                force: false,
                backend: BackendChoice::SevenZ,
                argon2id: true,
                mlkem: false,
                dry_run: false,
                resume: false,
                argon2_memory_kib: 65536,
                argon2_iterations: 3,
                argon2_parallelism: 4,
            },
        };
        let result = run(cli);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("--argon2id/--mlkem only supported with --backend age"));
    }

    #[test]
    fn test_age_backend_with_mlkem_accepted() {
        let cli = Cli {
            command: Commands::Pack {
                source: PathBuf::from("/tmp/fake"),
                output: None,
                password: Some("test".to_string()),
                confirm_password: false,
                compression_level: None,
                delete_source: false,
                secure_delete: false,
                force: false,
                backend: BackendChoice::Age,
                argon2id: false,
                mlkem: true,
                dry_run: false,
                resume: false,
                argon2_memory_kib: 65536,
                argon2_iterations: 3,
                argon2_parallelism: 4,
            },
        };
        let result = run(cli);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(!err_msg.contains("--argon2id/--mlkem only supported with --backend age"));
    }

    #[test]
    fn test_resume_does_not_falsely_report_completion() {
        let tmp = tempfile::TempDir::new().unwrap();
        let source = tmp.path().join("data.txt");
        std::fs::write(&source, b"some content for resume test").unwrap();

        let archive_path = tmp.path().join("data.age.tar.zst");
        let checksum = ramz_core::resume::compute_file_checksum(&source).unwrap();

        // شبیه‌سازی وضعیت "قطع‌شده": resume state با processed_bytes=0 ذخیره شده
        // ولی هیچ آرشیوی روی دیسک وجود نداره - دقیقاً همون سناریویی که با
        // timeout دستی تست کردیم
        // simulate an "interrupted" state: resume state saved with
        // processed_bytes=0, but no archive file exists on disk - exactly what
        // we reproduced manually with `timeout`
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
