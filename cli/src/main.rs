use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use ramz_core::{safe_output_dir, Backend, PackOptions, ProgressReporter, RamzError, Target};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Engine {
    // موتور پیش‌فرض: مدرن، امن، بدون وابستگی به باینری خارجی
    // Default engine: modern, secure, no external binary dependency
    #[value(help = "Modern, secure, no external binary dependency")]
    Age,
    // حالت سازگاری با ابزارهای دیگه (نیازمند نصب 7z)
    // Compatibility mode with other tools (requires 7z installed)
    #[value(help = "Compatibility mode with other tools (requires 7z installed)")]
    Compat7z,
}

#[derive(Parser, Debug)]
#[command(name = "ramz", version, about = "Secure cross-platform archive tool")]
struct Cli {
    // مسیر فایل یا پوشه‌ی مبدا
    // Path to the source file or directory
    #[arg(help = "Path to the source file or directory")]
    path: PathBuf,

    // موتور رمزنگاری
    // Encryption engine
    #[arg(
        short,
        long,
        value_enum,
        default_value = "age",
        help = "Encryption engine to use"
    )]
    engine: Engine,

    // پوشه‌ی خروجی (پیش‌فرض: همون پوشه‌ی مبدا)
    // Output directory (default: same as source)
    #[arg(short, long, help = "Output directory (default: same as source)")]
    output: Option<PathBuf>,

    // حذف مبدا پس از تایید موفقیت‌آمیز بودن آرشیو
    // Delete the source after successful verification
    #[arg(
        short,
        long,
        default_value_t = false,
        help = "Delete the source after successful verification"
    )]
    delete_source: bool,

    // غیرفعال کردن رمزگذاری (فقط فشرده‌سازی)؛ باید صراحتاً درخواست بشه
    // Disable encryption (compression only); must be explicitly requested
    #[arg(
        long,
        default_value_t = false,
        help = "Disable encryption, compression only (must be explicit)"
    )]
    no_password: bool,

    // سطح فشرده‌سازی صفر تا نه
    // Compression level zero to nine
    #[arg(
        short,
        long,
        default_value_t = 9,
        help = "Compression level, zero to nine"
    )]
    compression: u8,

    // بازنویسی آرشیو خروجی در صورت وجود
    // Overwrite the output archive if it already exists
    #[arg(
        short,
        long,
        default_value_t = false,
        help = "Overwrite the output archive if it already exists"
    )]
    force: bool,
}

struct CliProgress {
    bar: ProgressBar,
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

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let target = Target::detect(&cli.path)?;

    let backend: Box<dyn Backend> = match cli.engine {
        Engine::Age => Box::new(ramz_backend_age::AgeBackend),
        Engine::Compat7z => Box::new(ramz_backend_7z::SevenZBackend),
    };

    if backend.requires_external_binary() {
        // بررسی وجود باینری قبل از شروع، تا کاربر زودتر بفهمه
        // Check for the external binary up front, so the user finds out early
        println!("Using {} engine (external binary required).", backend.name());
    }

    let output_dir = safe_output_dir(&cli.path, cli.output.as_deref());

    let base_name = target
        .path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("archive");

    let archive_path = output_dir.join(format!("{base_name}.{}", backend.extension()));

    if archive_path.exists() && !cli.force {
        return Err(RamzError::Backend(format!(
            "archive already exists (use --force to overwrite): {}",
            archive_path.display()
        ))
        .into());
    }

    println!("Target: {} ({:?})", target.path.display(), target.kind);
    println!("Total size: {}", human_bytes(target.total_bytes));

    let password = if cli.no_password {
        None
    } else {
        Some(ramz_core::read_and_confirm_password(
            || rpassword::prompt_password("Enter archive password: "),
            || rpassword::prompt_password("Confirm password: "),
        )?)
    };

    if matches!(cli.engine, Engine::Age) && password.is_none() {
        return Err(anyhow::anyhow!(
            "the age engine requires a password; pass a different engine if you need unencrypted output"
        ));
    }

    let opts = PackOptions {
        password: password.clone(),
        compression_level: cli.compression,
        delete_source: cli.delete_source,
        output_dir: Some(output_dir),
        force_overwrite: cli.force,
    };

    let bar = ProgressBar::new(target.total_bytes);
    bar.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})",
        )
        .unwrap()
        .progress_chars("#>-"),
    );
    let mut progress = CliProgress { bar };

    backend.pack(&target, &archive_path, &opts, &mut progress)?;

    println!("Verifying archive integrity...");
    backend.verify(&archive_path, password.as_deref())?;
    println!("Archive verified: {}", archive_path.display());

    if cli.delete_source {
        match target.kind {
            ramz_core::SourceKind::Directory => std::fs::remove_dir_all(&target.path)?,
            ramz_core::SourceKind::File => std::fs::remove_file(&target.path)?,
        }
        println!("Source removed: {}", target.path.display());
    } else {
        println!("Source kept: {}", target.path.display());
    }

    Ok(())
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    format!("{size:.2} {}", UNITS[unit])
}
