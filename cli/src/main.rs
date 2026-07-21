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
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║          DRY RUN PREVIEW                             ║");
    println!("╠══════════════════════════════════════════════════════╣");
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
    println!("╠══════════════════════════════════════════════════════╣");
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
    println!("╚══════════════════════════════════════════════════════╝\n");
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Pack {
            source,
            output,
            password,
            confirm_password,
            compression_level,
            delete_source,
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
                    match ramz_core::resume::verify_source_unchanged(&state)? {
                        true => {
                            println!(
                                "Resume: source unchanged since last run. Archive already complete."
                            );
                            return Ok(());
                        }
                        false => {
                            return Err(RamzError::ResumeMismatch(
                                "source has changed since last run; cannot resume".into(),
                            )
                            .into());
                        }
                    }
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
                if target.kind == ramz_core::SourceKind::Directory {
                    fs::remove_dir_all(&source)?;
                } else {
                    fs::remove_file(&source)?;
                }
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
