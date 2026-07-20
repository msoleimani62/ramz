use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

use ramz_core::{Backend, PackOptions, ProgressReporter, RamzError, Result, SourceKind, Target};
use regex::Regex;

pub struct SevenZBackend;

fn find_binary() -> Result<String> {
    for candidate in ["7z", "7zz", "7za"] {
        if which::which(candidate).is_ok() {
            return Ok(candidate.to_string());
        }
    }
    Err(RamzError::Backend(
        "no 7z binary found (tried 7z, 7zz, 7za) — install p7zip/7zip package".into(),
    ))
}

impl Backend for SevenZBackend {
    fn name(&self) -> &'static str {
        "7z"
    }

    fn extension(&self) -> &'static str {
        "7z"
    }

    fn requires_external_binary(&self) -> bool {
        true
    }

    fn pack(
        &self,
        target: &Target,
        archive_path: &Path,
        opts: &PackOptions,
        progress: &mut dyn ProgressReporter,
    ) -> Result<()> {
        progress.set_total(target.total_bytes);

        let binary = find_binary()?;
        let mut cmd = Command::new(&binary);
        cmd.arg("a")
            .arg("-t7z")
            .arg(format!("-mx={}", opts.compression_level.clamp(0, 9)))
            .arg("-bsp1");

        if let Some(pw) = &opts.password {
            cmd.arg("-mhe=on").arg(format!("-p{pw}"));
        }

        cmd.arg(archive_path);

        match target.kind {
            SourceKind::Directory => {
                cmd.arg(&target.path);
            }
            SourceKind::File => {
                cmd.arg(&target.path);
            }
        }

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| RamzError::Backend(format!("failed to spawn {binary}: {e}")))?;

        let stdout = child.stdout.take().expect("stdout piped");
        let reader = BufReader::new(stdout);
        let percent_re = Regex::new(r"(\d+)%").unwrap();

        for line in reader.lines().flatten() {
            if let Some(caps) = percent_re.captures(&line) {
                if let Ok(pct) = caps[1].parse::<u64>() {
                    let processed = target.total_bytes.saturating_mul(pct) / 100;
                    progress.on_progress(processed);
                }
            }
        }

        let stderr = child.stderr.take().expect("stderr piped");
        let stderr_reader = BufReader::new(stderr);
        let mut stderr_lines = Vec::new();
        for line in stderr_reader.lines().flatten() {
            if !line.trim().is_empty() {
                stderr_lines.push(line);
            }
        }

        let status = child
            .wait()
            .map_err(|e| RamzError::Backend(format!("failed to wait on {binary}: {e}")))?;

        if !status.success() {
            let stderr_msg = if stderr_lines.is_empty() {
                format!("{binary} exited with status {status}")
            } else {
                format!(
                    "{binary} exited with status {status}: {}",
                    stderr_lines.join("; ")
                )
            };
            return Err(RamzError::Backend(stderr_msg));
        }

        progress.finish("7z archive complete");
        Ok(())
    }

    fn verify(&self, archive_path: &Path, password: Option<&str>) -> Result<()> {
        let binary = find_binary()?;
        let mut cmd = Command::new(&binary);
        cmd.arg("t").arg(archive_path);
        if let Some(pw) = password {
            cmd.arg(format!("-p{pw}"));
        }
        cmd.stdout(Stdio::null()).stderr(Stdio::piped());

        let output = cmd
            .output()
            .map_err(|e| RamzError::Backend(format!("failed to run {binary} test: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RamzError::VerificationFailed(stderr.to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sevenz_backend_name() {
        let backend = SevenZBackend;
        assert_eq!(backend.name(), "7z");
        assert_eq!(backend.extension(), "7z");
        assert!(backend.requires_external_binary());
    }
}
