// fort-release: dev-only release helper (never shipped in archives or formulae).
//
// Mirrors the proven si-release command shape (self/installer/homebrew; no npm
// group: Fort ships via GitHub Releases + Homebrew only). All orchestration is
// Rust; system tools (cargo, tar, brew) are invoked as subprocesses.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use sha2::{Digest, Sha256};

const RELEASE_BINS: [&str; 3] = ["fort", "fortd", "fort-agent"];
const MATRIX_TARGETS: [(&str, &str); 4] = [
    ("linux", "amd64"),
    ("linux", "arm64"),
    ("darwin", "amd64"),
    ("darwin", "arm64"),
];

#[derive(Parser)]
#[command(
    name = "fort-release",
    about = "Dev-only Fort release helper (never shipped)",
    long_about = "Build, verify, and smoke Fort release artifacts from the canonical Cargo.toml version. Groups: self (version gate, asset build/verify), installer (host and Homebrew smokes), homebrew (tap formula rendering)."
)]
struct Cli {
    #[command(subcommand)]
    command: TopCommand,
}

#[derive(Subcommand)]
enum TopCommand {
    #[command(name = "self", about = "Release-asset operations for this checkout")]
    Slf(SelfCommand),
    #[command(about = "Installer smoke tests")]
    Installer(InstallerCommand),
    #[command(about = "Homebrew tap operations")]
    Homebrew(HomebrewCommand),
}

#[derive(Args)]
struct SelfCommand {
    #[command(subcommand)]
    command: SelfSubcommand,
}

#[derive(Subcommand)]
enum SelfSubcommand {
    #[command(about = "Check a release tag against the canonical Cargo.toml version")]
    ValidateVersion(ValidateVersionArgs),
    #[command(about = "Build the current-host release archive and checksums layout")]
    Assets(AssetsArgs),
    #[command(about = "Verify release archives and checksums in a directory")]
    Verify(VerifyArgs),
}

#[derive(Args)]
struct ValidateVersionArgs {
    #[arg(long, help = "Release tag to validate, e.g. v1.1.0")]
    tag: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Allow patch tags (rehearsals only; published releases are minor-only)"
    )]
    allow_patch: bool,
}

#[derive(Args)]
struct AssetsArgs {
    #[arg(long, help = "Directory the archive and checksums are written to")]
    out_dir: PathBuf,
    #[arg(
        long,
        help = "Version to package (defaults to the canonical Cargo.toml version)"
    )]
    version: Option<String>,
}

#[derive(Args)]
struct VerifyArgs {
    #[arg(
        long,
        help = "Version the archives must belong to (defaults to the canonical version)"
    )]
    version: Option<String>,
    #[arg(long, help = "Directory holding release archives and checksums.txt")]
    out_dir: PathBuf,
}

#[derive(Args)]
struct InstallerCommand {
    #[command(subcommand)]
    command: InstallerSubcommand,
}

#[derive(Subcommand)]
enum InstallerSubcommand {
    #[command(about = "Build and exercise the CLI on the current host")]
    SmokeHost,
    #[command(about = "Render a formula into a temp tap and optionally brew-install it")]
    SmokeHomebrew(SmokeHomebrewArgs),
}

#[derive(Args)]
struct SmokeHomebrewArgs {
    #[arg(long, help = "Tap directory to render into (defaults to a temp dir)")]
    tap_dir: Option<PathBuf>,
    #[arg(long, help = "Version to smoke (defaults to the canonical version)")]
    version: Option<String>,
    #[arg(long, help = "checksums.txt file or URL for the version under test")]
    checksums: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Perform a real brew install from the temp tap (requires published assets)"
    )]
    install: bool,
}

#[derive(Args)]
struct HomebrewCommand {
    #[command(subcommand)]
    command: HomebrewSubcommand,
}

#[derive(Subcommand)]
enum HomebrewSubcommand {
    #[command(about = "Render Formula/fort.rb and bump the tap VERSION file")]
    RenderTapFormula(RenderTapFormulaArgs),
}

#[derive(Args)]
struct RenderTapFormulaArgs {
    #[arg(
        long,
        help = "Release tag, e.g. v1.1.0 (defaults to v<canonical version>)"
    )]
    version: Option<String>,
    #[arg(long, help = "checksums.txt file path or https URL")]
    checksums: String,
    #[arg(long, help = "Tap repository root (Formula/ and VERSION live here)")]
    tap_dir: PathBuf,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("fort-release: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        TopCommand::Slf(cmd) => match cmd.command {
            SelfSubcommand::ValidateVersion(args) => cmd_validate_version(&args),
            SelfSubcommand::Assets(args) => cmd_assets(&args),
            SelfSubcommand::Verify(args) => cmd_verify(&args),
        },
        TopCommand::Installer(cmd) => match cmd.command {
            InstallerSubcommand::SmokeHost => cmd_smoke_host(),
            InstallerSubcommand::SmokeHomebrew(args) => cmd_smoke_homebrew(&args),
        },
        TopCommand::Homebrew(cmd) => match cmd.command {
            HomebrewSubcommand::RenderTapFormula(args) => {
                let rendered = cmd_render_tap_formula(&args)?;
                println!(
                    "updated {} for {}",
                    rendered.display(),
                    args.version.as_deref().unwrap_or("canonical version")
                );
                Ok(())
            }
        },
    }
}

fn canonical_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn parse_version_tag(tag: &str) -> Result<(u64, u64, u64)> {
    let nov = tag
        .trim()
        .strip_prefix('v')
        .ok_or_else(|| anyhow::anyhow!("version tag must include v prefix: {tag}"))?;
    let mut parts = nov.split('.');
    let (Some(major), Some(minor), Some(patch), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("version tag must be vX.Y.Z: {tag}");
    };
    let parse = |label: &str, raw: &str| {
        raw.parse::<u64>()
            .with_context(|| format!("invalid {label} in version tag: {tag}"))
    };
    Ok((
        parse("major", major)?,
        parse("minor", minor)?,
        parse("patch", patch)?,
    ))
}

fn cmd_validate_version(args: &ValidateVersionArgs) -> Result<()> {
    let (major, minor, patch) = parse_version_tag(&args.tag)?;
    let canonical = canonical_version();
    let expected_tag = format!("v{canonical}");
    if args.tag.trim() != expected_tag {
        bail!(
            "tag {} does not match Cargo.toml version {canonical}",
            args.tag.trim()
        );
    }
    if patch != 0 && !args.allow_patch {
        bail!(
            "{major}.{minor}.{patch} is a patch version: published releases are minor-only (vX.Y.0)"
        );
    }
    println!(
        "tag {} matches package version {canonical}",
        args.tag.trim()
    );
    Ok(())
}

fn run_step(program: &str, args: &[&str], workdir: Option<&Path>) -> Result<()> {
    println!("+ {} {}", program, args.join(" "));
    let mut cmd = ProcCommand::new(program);
    cmd.args(args);
    if let Some(dir) = workdir {
        cmd.current_dir(dir);
    }
    let status = cmd.status().with_context(|| format!("run {program}"))?;
    if !status.success() {
        bail!("{program} exited with {status}");
    }
    Ok(())
}

fn capture_step(program: &str, args: &[&str], workdir: Option<&Path>) -> Result<String> {
    let mut cmd = ProcCommand::new(program);
    cmd.args(args);
    if let Some(dir) = workdir {
        cmd.current_dir(dir);
    }
    let output = cmd.output().with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn host_target() -> Result<(String, String)> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        other => bail!("unsupported release host os: {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => bail!("unsupported release host arch: {other}"),
    };
    Ok((os.to_string(), arch.to_string()))
}

fn release_bin_dir() -> Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        candidates.push(PathBuf::from(dir).join("release"));
    }
    candidates.push(PathBuf::from("target/release"));
    candidates.push(PathBuf::from(".artifacts/cargo-target/release"));
    for candidate in &candidates {
        if RELEASE_BINS.iter().all(|bin| candidate.join(bin).is_file()) {
            return Ok(candidate.clone());
        }
    }
    bail!(
        "release binaries not found under {}",
        candidates
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn cmd_assets(args: &AssetsArgs) -> Result<()> {
    let version = args
        .version
        .clone()
        .unwrap_or_else(|| canonical_version().to_string());
    let (os, arch) = host_target()?;
    fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("create {}", args.out_dir.display()))?;
    run_step(
        "cargo",
        &[
            "build",
            "--locked",
            "--release",
            "--bin",
            "fort",
            "--bin",
            "fortd",
            "--bin",
            "fort-agent",
        ],
        None,
    )?;
    let bin_dir = release_bin_dir()?;
    for bin in RELEASE_BINS {
        let path = bin_dir.join(bin);
        if !path.is_file() {
            bail!("missing release binary {}", path.display());
        }
    }
    let reported = capture_step(
        bin_dir.join("fort").to_str().context("fort path")?,
        &["version"],
        None,
    )?;
    if reported.trim() != version {
        bail!(
            "built fort reports {} but packaging {version}",
            reported.trim()
        );
    }
    let archive_name = format!("fort_{version}_{os}_{arch}.tar.gz");
    let archive = args.out_dir.join(&archive_name);
    if archive.exists() {
        fs::remove_file(&archive).with_context(|| format!("remove {}", archive.display()))?;
    }
    run_step(
        "tar",
        &[
            "-czf",
            archive.to_str().context("archive path")?,
            "-C",
            bin_dir.to_str().context("bin dir")?,
            "fort",
            "fortd",
            "fort-agent",
        ],
        None,
    )?;
    let sha = sha256_file(&archive)?;
    let checksums = args.out_dir.join("checksums.txt");
    fs::write(&checksums, format!("{sha}  {archive_name}\n"))
        .with_context(|| format!("write {}", checksums.display()))?;
    println!("wrote {} and checksums.txt", archive.display());
    Ok(())
}

fn cmd_verify(args: &VerifyArgs) -> Result<()> {
    let version = args
        .version
        .clone()
        .unwrap_or_else(|| canonical_version().to_string());
    let checksums_path = args.out_dir.join("checksums.txt");
    let checksums_raw = fs::read_to_string(&checksums_path)
        .with_context(|| format!("read {}", checksums_path.display()))?;
    let mut expected = BTreeMap::new();
    for line in checksums_raw.lines() {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some(sha), Some(name)) => {
                expected.insert(name.to_string(), sha.to_string());
            }
            _ => bail!("malformed checksums line: {line}"),
        }
    }
    let mut archives: Vec<PathBuf> = Vec::new();
    for entry in
        fs::read_dir(&args.out_dir).with_context(|| format!("read {}", args.out_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(&format!("fort_{version}_")) && name.ends_with(".tar.gz") {
            archives.push(entry.path());
        }
    }
    if archives.is_empty() {
        bail!(
            "no fort_{version}_*.tar.gz archives in {}",
            args.out_dir.display()
        );
    }
    archives.sort();
    for archive in &archives {
        let name = archive
            .file_name()
            .context("archive name")?
            .to_string_lossy()
            .to_string();
        let want = expected
            .get(&name)
            .with_context(|| format!("{name} missing from checksums.txt"))?;
        let got = sha256_file(archive)?;
        if &got != want {
            bail!("checksum mismatch for {name}");
        }
        let members = capture_step(
            "tar",
            &["-tzf", archive.to_str().context("archive path")?],
            None,
        )?;
        if !members.lines().any(|line| line.trim() == "fort") {
            bail!("{name} is missing the fort binary");
        }
        let probe = tempfile::tempdir().context("probe dir")?;
        run_step(
            "tar",
            &[
                "-xzf",
                archive.to_str().context("archive path")?,
                "-C",
                probe.path().to_str().context("probe path")?,
            ],
            None,
        )?;
        let reported = capture_step(
            probe.path().join("fort").to_str().context("probe fort")?,
            &["version"],
            None,
        )?;
        if reported.trim() != version {
            bail!(
                "{name} fort reports {} but expected {version}",
                reported.trim()
            );
        }
        println!("verified {name}");
    }
    Ok(())
}

fn cmd_smoke_host() -> Result<()> {
    run_step("cargo", &["build", "--locked", "--bin", "fort"], None)?;
    let candidates = [
        PathBuf::from("target/debug/fort"),
        PathBuf::from(".artifacts/cargo-target/debug/fort"),
    ];
    let fort = candidates
        .into_iter()
        .find(|path| path.is_file())
        .context("built fort binary not found")?;
    let reported = capture_step(fort.to_str().context("fort path")?, &["version"], None)?;
    if reported.trim() != canonical_version() {
        bail!(
            "smoke fort reports {} but canonical version is {}",
            reported.trim(),
            canonical_version()
        );
    }
    for page in [
        &["--help"] as &[&str],
        &["auth", "github", "login", "--help"],
    ] {
        let text = capture_step(fort.to_str().context("fort path")?, page, None)?;
        if !text.contains("Usage:") {
            bail!("smoke help page {:?} has no Usage line", page);
        }
    }
    println!("host smoke ok for {}", canonical_version());
    Ok(())
}

fn read_checksums_map(checksums_ref: &str) -> Result<BTreeMap<String, String>> {
    let raw = if checksums_ref.starts_with("http://") || checksums_ref.starts_with("https://") {
        reqwest::blocking::get(checksums_ref)
            .with_context(|| format!("fetch {checksums_ref}"))?
            .error_for_status()
            .with_context(|| format!("fetch {checksums_ref}"))?
            .text()
            .with_context(|| format!("read {checksums_ref}"))?
    } else {
        fs::read_to_string(checksums_ref)
            .with_context(|| format!("read checksums file {checksums_ref}"))?
    };
    let mut map = BTreeMap::new();
    for line in raw.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some(sha), Some(name)) => {
                if sha.len() != 64 || !sha.chars().all(|ch| ch.is_ascii_hexdigit()) {
                    bail!("malformed sha256 for {name}");
                }
                map.insert(name.to_string(), sha.to_string());
            }
            _ => bail!("malformed checksums line: {line}"),
        }
    }
    Ok(map)
}

fn archive_name(version_nov: &str, os: &str, arch: &str) -> String {
    format!("fort_{version_nov}_{os}_{arch}.tar.gz")
}

#[allow(clippy::too_many_arguments)]
fn render_formula(
    version_tag: &str,
    version_nov: &str,
    sha_darwin_arm64: &str,
    sha_darwin_amd64: &str,
    sha_linux_arm64: &str,
    sha_linux_amd64: &str,
) -> String {
    let asset_darwin_arm64 = archive_name(version_nov, "darwin", "arm64");
    let asset_darwin_amd64 = archive_name(version_nov, "darwin", "amd64");
    let asset_linux_arm64 = archive_name(version_nov, "linux", "arm64");
    let asset_linux_amd64 = archive_name(version_nov, "linux", "amd64");
    format!(
        "class Fort < Formula\n  desc \"Policy and authentication API for Vault secret operations\"\n  homepage \"https://github.com/Aureuma/fort\"\n  version \"{version_nov}\"\n  license \"AGPL-3.0-only\"\n\n  on_macos do\n    if Hardware::CPU.arm?\n      url \"https://github.com/Aureuma/fort/releases/download/{version_tag}/{asset_darwin_arm64}\"\n      sha256 \"{sha_darwin_arm64}\"\n    else\n      url \"https://github.com/Aureuma/fort/releases/download/{version_tag}/{asset_darwin_amd64}\"\n      sha256 \"{sha_darwin_amd64}\"\n    end\n  end\n\n  on_linux do\n    if Hardware::CPU.arm?\n      url \"https://github.com/Aureuma/fort/releases/download/{version_tag}/{asset_linux_arm64}\"\n      sha256 \"{sha_linux_arm64}\"\n    elsif Hardware::CPU.intel?\n      url \"https://github.com/Aureuma/fort/releases/download/{version_tag}/{asset_linux_amd64}\"\n      sha256 \"{sha_linux_amd64}\"\n    end\n  end\n\n  def install\n    stage = buildpath/\"fort-stage\"\n    stage.mkpath\n    system \"tar\", \"-xzf\", cached_download, \"-C\", stage\n\n    binary = Dir[\"#{{stage}}/fort_*/fort\"].first\n    binary = (stage/\"fort\").to_s if binary.nil? && (stage/\"fort\").exist?\n    raise \"fort binary not found in release archive\" if binary.nil? || binary.empty?\n\n    bin.install binary => \"fort\"\n    chmod 0o755, bin/\"fort\"\n  end\n\n  test do\n    output = shell_output(\"#{{bin}}/fort version\")\n    assert_match version.to_s, output\n  end\nend\n"
    )
}

fn lookup_sha<'a>(map: &'a BTreeMap<String, String>, asset: &str) -> Result<&'a str> {
    map.get(asset)
        .map(String::as_str)
        .with_context(|| format!("checksum not found for {asset}"))
}

fn bump_tap_version(tap_dir: &Path) -> Result<String> {
    let path = tap_dir.join("VERSION");
    let next = match fs::read_to_string(&path) {
        Ok(raw) => {
            let mut parts = raw.trim().split('.');
            let (Some(major), Some(minor), Some(patch), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                bail!("malformed tap VERSION: {}", raw.trim());
            };
            let patch_num: u64 = patch
                .parse()
                .with_context(|| format!("malformed tap VERSION: {}", raw.trim()))?;
            format!("{major}.{minor}.{}\n", patch_num + 1)
        }
        Err(_) => "0.0.1\n".to_string(),
    };
    fs::write(&path, &next).with_context(|| format!("write {}", path.display()))?;
    Ok(next.trim().to_string())
}

fn cmd_render_tap_formula(args: &RenderTapFormulaArgs) -> Result<PathBuf> {
    let tag = args
        .version
        .clone()
        .unwrap_or_else(|| format!("v{}", canonical_version()));
    parse_version_tag(&tag)?;
    let version_nov = tag.trim().trim_start_matches('v').to_string();
    let map = read_checksums_map(&args.checksums)?;
    let mut shas = BTreeMap::new();
    for (os, arch) in MATRIX_TARGETS {
        let asset = archive_name(&version_nov, os, arch);
        shas.insert(
            format!("{os}_{arch}"),
            lookup_sha(&map, &asset)?.to_string(),
        );
    }
    let formula = render_formula(
        tag.trim(),
        &version_nov,
        &shas["darwin_arm64"],
        &shas["darwin_amd64"],
        &shas["linux_arm64"],
        &shas["linux_amd64"],
    );
    let formula_dir = args.tap_dir.join("Formula");
    fs::create_dir_all(&formula_dir)
        .with_context(|| format!("create {}", formula_dir.display()))?;
    let formula_path = formula_dir.join("fort.rb");
    fs::write(&formula_path, &formula)
        .with_context(|| format!("write {}", formula_path.display()))?;
    let tap_version = bump_tap_version(&args.tap_dir)?;
    println!("tap VERSION is now {tap_version}");
    Ok(formula_path)
}

fn brew_available() -> bool {
    ProcCommand::new("brew")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn cmd_smoke_homebrew(args: &SmokeHomebrewArgs) -> Result<()> {
    let version = args
        .version
        .clone()
        .unwrap_or_else(|| canonical_version().to_string());
    let tag = format!("v{version}");
    parse_version_tag(&tag)?;
    let temp_tap = tempfile::tempdir().context("temp tap dir")?;
    let tap_dir = args
        .tap_dir
        .clone()
        .unwrap_or_else(|| temp_tap.path().to_path_buf());
    let formula_path = cmd_render_tap_formula(&RenderTapFormulaArgs {
        version: Some(tag.clone()),
        checksums: args.checksums.clone(),
        tap_dir: tap_dir.clone(),
    })?;
    let rendered = fs::read_to_string(&formula_path)
        .with_context(|| format!("read {}", formula_path.display()))?;
    if !rendered.contains(&format!("version \"{version}\"")) {
        bail!("rendered formula is missing version {version}");
    }
    for (os, arch) in MATRIX_TARGETS {
        let asset = archive_name(&version, os, arch);
        if !rendered.contains(&asset) {
            bail!("rendered formula is missing {asset}");
        }
    }
    println!("formula render ok for {tag}");
    if !args.install {
        if brew_available() {
            println!("render-only smoke (pass --install for a real brew install)");
        } else {
            println!("WARNING: brew not found; install step SKIPPED (render validated only)");
        }
        return Ok(());
    }
    if !brew_available() {
        bail!("brew is required for --install");
    }
    // Real local-tap flow: plain file installs are rejected by Homebrew, so
    // the rendered formula goes through a temporary tap.
    let tap = "fort-local/smoke";
    let _ = ProcCommand::new("brew").args(["untap", tap]).output().ok();
    let tapped = ProcCommand::new("brew")
        .arg("tap")
        .output()
        .is_ok_and(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line.trim() == tap)
        });
    if !tapped {
        run_step("brew", &["tap-new", tap], None)?;
    }
    let tap_root = capture_step("brew", &["--repository", tap], None)?;
    let tap_formula_dir = Path::new(tap_root.trim()).join("Formula");
    fs::create_dir_all(&tap_formula_dir)
        .with_context(|| format!("create {}", tap_formula_dir.display()))?;
    fs::copy(&formula_path, tap_formula_dir.join("fort.rb"))
        .with_context(|| format!("stage {} into temp tap", formula_path.display()))?;
    // Newer brews distrust temp taps; older brews lack the subcommand.
    let _ = ProcCommand::new("brew").args(["trust", tap]).output().ok();
    let already_installed = ProcCommand::new("brew")
        .args(["list", "fort"])
        .output()
        .is_ok_and(|output| output.status.success());
    let qualified = format!("{tap}/fort");
    if already_installed {
        run_step("brew", &["reinstall", &qualified], None)?;
    } else {
        run_step("brew", &["install", &qualified], None)?;
    }
    let prefix = capture_step("brew", &["--prefix", "fort"], None)?;
    let brewed = Path::new(prefix.trim()).join("bin/fort");
    let reported = capture_step(
        brewed.to_str().context("brewed fort path")?,
        &["version"],
        None,
    )?;
    if reported.trim() != version {
        bail!(
            "brewed fort reports {} but expected {version}",
            reported.trim()
        );
    }
    run_step("brew", &["test", &qualified], None)?;
    match run_step("brew", &["untap", tap], None) {
        Ok(()) => {}
        Err(error) => println!("WARNING: temp tap cleanup failed (harmless): {error:#}"),
    }
    println!("homebrew smoke ok for {tag}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_shas() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("fort_9.9.9_darwin_arm64.tar.gz".to_string(), "a".repeat(64)),
            ("fort_9.9.9_darwin_amd64.tar.gz".to_string(), "b".repeat(64)),
            ("fort_9.9.9_linux_arm64.tar.gz".to_string(), "c".repeat(64)),
            ("fort_9.9.9_linux_amd64.tar.gz".to_string(), "d".repeat(64)),
        ])
    }

    #[test]
    fn golden_formula_matches_shell_renderer_shape() {
        let map = fixture_shas();
        let formula = render_formula(
            "v9.9.9",
            "9.9.9",
            lookup_sha(&map, "fort_9.9.9_darwin_arm64.tar.gz").unwrap(),
            lookup_sha(&map, "fort_9.9.9_darwin_amd64.tar.gz").unwrap(),
            lookup_sha(&map, "fort_9.9.9_linux_arm64.tar.gz").unwrap(),
            lookup_sha(&map, "fort_9.9.9_linux_amd64.tar.gz").unwrap(),
        );
        let (a, b, c, d) = (
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
        );
        let expected = format!(
            "class Fort < Formula\n  desc \"Policy and authentication API for Vault secret operations\"\n  homepage \"https://github.com/Aureuma/fort\"\n  version \"9.9.9\"\n  license \"AGPL-3.0-only\"\n\n  on_macos do\n    if Hardware::CPU.arm?\n      url \"https://github.com/Aureuma/fort/releases/download/v9.9.9/fort_9.9.9_darwin_arm64.tar.gz\"\n      sha256 \"{a}\"\n    else\n      url \"https://github.com/Aureuma/fort/releases/download/v9.9.9/fort_9.9.9_darwin_amd64.tar.gz\"\n      sha256 \"{b}\"\n    end\n  end\n\n  on_linux do\n    if Hardware::CPU.arm?\n      url \"https://github.com/Aureuma/fort/releases/download/v9.9.9/fort_9.9.9_linux_arm64.tar.gz\"\n      sha256 \"{c}\"\n    elsif Hardware::CPU.intel?\n      url \"https://github.com/Aureuma/fort/releases/download/v9.9.9/fort_9.9.9_linux_amd64.tar.gz\"\n      sha256 \"{d}\"\n    end\n  end\n\n  def install\n    stage = buildpath/\"fort-stage\"\n    stage.mkpath\n    system \"tar\", \"-xzf\", cached_download, \"-C\", stage\n\n    binary = Dir[\"#{{stage}}/fort_*/fort\"].first\n    binary = (stage/\"fort\").to_s if binary.nil? && (stage/\"fort\").exist?\n    raise \"fort binary not found in release archive\" if binary.nil? || binary.empty?\n\n    bin.install binary => \"fort\"\n    chmod 0o755, bin/\"fort\"\n  end\n\n  test do\n    output = shell_output(\"#{{bin}}/fort version\")\n    assert_match version.to_s, output\n  end\nend\n"
        );
        assert_eq!(formula, expected);
    }

    #[test]
    fn version_tag_parses_and_rejects() {
        assert_eq!(parse_version_tag("v1.1.0").unwrap(), (1, 1, 0));
        assert!(parse_version_tag("1.1.0").is_err());
        assert!(parse_version_tag("v1.1").is_err());
        assert!(parse_version_tag("v1.1.0.0").is_err());
        assert!(parse_version_tag("v1.x.0").is_err());
    }

    #[test]
    fn checksums_map_parses_and_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checksums.txt");
        let sha = "e".repeat(64);
        fs::write(&path, format!("{sha}  fort_1.2.3_linux_amd64.tar.gz\n")).unwrap();
        let map = read_checksums_map(path.to_str().unwrap()).unwrap();
        assert_eq!(map["fort_1.2.3_linux_amd64.tar.gz"], sha);
        fs::write(&path, "not-a-checksum-line\n").unwrap();
        assert!(read_checksums_map(path.to_str().unwrap()).is_err());
        fs::write(&path, "zz  some.tar.gz\n").unwrap();
        assert!(read_checksums_map(path.to_str().unwrap()).is_err());
    }

    #[test]
    fn tap_version_bumps_and_inits() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(bump_tap_version(dir.path()).unwrap(), "0.0.1");
        assert_eq!(bump_tap_version(dir.path()).unwrap(), "0.0.2");
        fs::write(dir.path().join("VERSION"), "1.2.3\n").unwrap();
        assert_eq!(bump_tap_version(dir.path()).unwrap(), "1.2.4");
        fs::write(dir.path().join("VERSION"), "bogus\n").unwrap();
        assert!(bump_tap_version(dir.path()).is_err());
    }
}
