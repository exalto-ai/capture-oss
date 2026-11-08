//! Deterministic transport archives for trace package packages.
//!
//! This module is shared by Trace sharing clients and the admission service. It
//! deliberately accepts only the six entries emitted by `notarize`; a transport
//! archive is not a generic ZIP file.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::Path,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use zip::{CompressionMethod, DateTime, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::sha256_hex;
pub use crate::{TRACE_EVIDENCE_FORMAT, WITNESS_EVIDENCE_FORMAT};

pub const TRACE_PACKAGE_FORMAT: &str = "ecp/trace-package/v1";
pub const ARCHIVE_CONTENT_TYPE: &str = "application/vnd.exalto.notary.trace-package+zip";
pub const ARCHIVE_MANIFEST_PATH: &str = "archive-manifest.json";
/// Entries of a Notarized package, whose evidence is a TLSNotary presentation.
pub const PACKAGE_FILES: [&str; 5] = [
    "evidence.tlsn",
    "manifest.json",
    "request.disclosed.http",
    "response.disclosed.http",
    "trace.otlp.json",
];
/// Entries of a Witnessed package, whose evidence is a notary witness receipt.
pub const WITNESSED_PACKAGE_FILES: [&str; 5] = [
    "evidence.witness",
    "manifest.json",
    "request.disclosed.http",
    "response.disclosed.http",
    "trace.otlp.json",
];

/// How a trace package's evidence was produced. This is a trust level, not a
/// state: a Notarized package carries a TLSNotary proof, a Witnessed package
/// carries the notary operator's signed receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum EvidenceKind {
    Notarized,
    Witnessed,
}

impl EvidenceKind {
    /// The versioned evidence format named by both package manifests.
    pub const fn evidence_format(self) -> &'static str {
        match self {
            Self::Notarized => TRACE_EVIDENCE_FORMAT,
            Self::Witnessed => WITNESS_EVIDENCE_FORMAT,
        }
    }

    /// The canonical, sorted package entries for this evidence kind.
    pub const fn package_files(self) -> [&'static str; 5] {
        match self {
            Self::Notarized => PACKAGE_FILES,
            Self::Witnessed => WITNESSED_PACKAGE_FILES,
        }
    }

    /// The entry holding the evidence itself.
    pub const fn evidence_entry(self) -> &'static str {
        self.package_files()[0]
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Notarized => "notarized",
            Self::Witnessed => "witnessed",
        }
    }

    pub fn from_evidence_format(format: &str) -> Option<Self> {
        [Self::Notarized, Self::Witnessed]
            .into_iter()
            .find(|kind| kind.evidence_format() == format)
    }

    fn from_evidence_entry(name: &str) -> Option<Self> {
        [Self::Notarized, Self::Witnessed]
            .into_iter()
            .find(|kind| kind.evidence_entry() == name)
    }
}
pub const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ARCHIVE_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_ZIP_CONTAINER_BYTES: u64 = 16 * 1024;
const MAX_REWRITTEN_COMPARISON_BYTES: usize = MAX_ZIP_CONTAINER_BYTES as usize;
/// Safe on-wire ceiling for the five Stored package entries, the bounded
/// archive manifest, and deterministic ZIP headers/directories.
pub const MAX_ARCHIVE_WIRE_BYTES: u64 =
    MAX_ARCHIVE_UNCOMPRESSED_BYTES + MAX_ARCHIVE_MANIFEST_BYTES + MAX_ZIP_CONTAINER_BYTES;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveFile {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TracePackageArchiveManifest {
    pub format: String,
    pub package_format: String,
    pub package_sha256: String,
    pub files: Vec<ArchiveFile>,
}

/// A canonical `.llmtrace` archive whose exact entry set, metadata, hashes,
/// and byte-for-byte ZIP encoding have already been validated.
pub struct ValidatedTracePackageArchive {
    pub manifest: TracePackageArchiveManifest,
    kind: EvidenceKind,
    files: BTreeMap<String, Vec<u8>>,
}

impl ValidatedTracePackageArchive {
    /// Returns how the package's evidence was produced.
    pub fn evidence_kind(&self) -> EvidenceKind {
        self.kind
    }

    /// Returns one required package entry. Callers cannot address arbitrary
    /// paths because validation has already restricted the archive to the
    /// versioned entry set.
    pub fn file(&self, name: &str) -> Result<&[u8]> {
        self.files.get(name).map(Vec::as_slice).ok_or_else(|| {
            anyhow!("trace package entry is not part of the current contract: {name}")
        })
    }

    pub(crate) fn into_files(self) -> BTreeMap<String, Vec<u8>> {
        self.files
    }
}

#[derive(Serialize)]
struct PackageDigest<'a> {
    format: &'a str,
    files: &'a [ArchiveFile],
}

/// The five already-produced entries that make up a verified trace package.
///
/// Naming the entries in the type prevents in-memory callers from supplying
/// arbitrary paths or omitting part of the versioned package contract.
pub(crate) struct TracePackageArchiveEntries<'a> {
    pub(crate) kind: EvidenceKind,
    pub(crate) evidence: &'a [u8],
    pub(crate) manifest_json: &'a [u8],
    pub(crate) request_disclosed_http: &'a [u8],
    pub(crate) response_disclosed_http: &'a [u8],
    pub(crate) trace_otlp_json: &'a [u8],
}

impl<'a> TracePackageArchiveEntries<'a> {
    fn into_files(self) -> BTreeMap<String, &'a [u8]> {
        BTreeMap::from([
            (self.kind.evidence_entry().to_owned(), self.evidence),
            ("manifest.json".to_owned(), self.manifest_json),
            (
                "request.disclosed.http".to_owned(),
                self.request_disclosed_http,
            ),
            (
                "response.disclosed.http".to_owned(),
                self.response_disclosed_http,
            ),
            ("trace.otlp.json".to_owned(), self.trace_otlp_json),
        ])
    }
}

/// Builds the exact bytes uploaded when a Trace is shared.
pub fn build_trace_package_archive(package: &Path) -> Result<Vec<u8>> {
    require_plain_directory(package)?;
    let kind = require_exact_package_entries(package)?;

    let evidence = read_regular_package_file(package, kind.evidence_entry())?;
    let manifest_json = read_regular_package_file(package, "manifest.json")?;
    let request_disclosed_http = read_regular_package_file(package, "request.disclosed.http")?;
    let response_disclosed_http = read_regular_package_file(package, "response.disclosed.http")?;
    let trace_otlp_json = read_regular_package_file(package, "trace.otlp.json")?;
    let entries = TracePackageArchiveEntries {
        kind,
        evidence: &evidence,
        manifest_json: &manifest_json,
        request_disclosed_http: &request_disclosed_http,
        response_disclosed_http: &response_disclosed_http,
        trace_otlp_json: &trace_otlp_json,
    };
    build_trace_package_archive_from_entries(entries)
}

/// Builds a canonical archive directly from its complete in-memory package.
pub(crate) fn build_trace_package_archive_from_entries(
    entries: TracePackageArchiveEntries,
) -> Result<Vec<u8>> {
    let kind = entries.kind;
    let files = entries.into_files();
    let mut file_manifest = Vec::with_capacity(kind.package_files().len());
    let mut total_size = 0u64;
    for name in kind.package_files() {
        let bytes = files
            .get(name)
            .expect("typed package entries contain every required file");
        total_size = total_size
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| anyhow!("trace package size overflow"))?;
        if total_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES {
            bail!("trace package exceeds the 128 MiB sharing limit");
        }
        file_manifest.push(ArchiveFile {
            path: name.to_owned(),
            size_bytes: bytes.len() as u64,
            sha256: sha256_hex(bytes),
        });
    }
    require_package_format(
        kind,
        files
            .get("manifest.json")
            .expect("required package manifest was loaded"),
    )?;

    let package_sha256 = package_digest(kind, &file_manifest)?;
    let archive_manifest = TracePackageArchiveManifest {
        format: TRACE_PACKAGE_FORMAT.to_owned(),
        package_format: kind.evidence_format().to_owned(),
        package_sha256,
        files: file_manifest,
    };
    let manifest_bytes =
        serde_json::to_vec(&archive_manifest).context("encoding archive manifest")?;
    if manifest_bytes.len() as u64 > MAX_ARCHIVE_MANIFEST_BYTES {
        bail!("archive manifest is unexpectedly large");
    }

    render_trace_package_archive(kind, &archive_manifest, &files)
}

fn read_regular_package_file(package: &Path, name: &str) -> Result<Vec<u8>> {
    let path = package.join(name);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("reading trace package entry {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("trace package entry must be a regular file: {name}");
    }
    fs::read(&path).with_context(|| format!("reading trace package entry {name}"))
}

fn render_trace_package_archive<V: AsRef<[u8]>>(
    kind: EvidenceKind,
    manifest: &TracePackageArchiveManifest,
    files: &BTreeMap<String, V>,
) -> Result<Vec<u8>> {
    let manifest_bytes = serde_json::to_vec(manifest).context("encoding archive manifest")?;
    let package_size = files.values().try_fold(0u64, |size, file| {
        size.checked_add(file.as_ref().len() as u64)
            .ok_or_else(|| anyhow!("trace package size overflow"))
    })?;
    let capacity = archive_capacity(package_size, manifest_bytes.len() as u64)?;
    let cursor = Cursor::new(Vec::with_capacity(capacity.try_into()?));
    let cursor = write_trace_package_archive(kind, &manifest_bytes, files, cursor)?;
    let archive = cursor.into_inner();
    if archive.len() as u64 > MAX_ARCHIVE_WIRE_BYTES {
        bail!("trace package archive exceeds the on-wire size limit");
    }
    Ok(archive)
}

fn write_trace_package_archive<W: Write + Seek, V: AsRef<[u8]>>(
    kind: EvidenceKind,
    manifest_bytes: &[u8],
    files: &BTreeMap<String, V>,
    output: W,
) -> Result<W> {
    let mut writer = ZipWriter::new(output);
    let options = deterministic_options();
    writer
        .start_file(ARCHIVE_MANIFEST_PATH, options)
        .context("starting archive manifest")?;
    writer
        .write_all(manifest_bytes)
        .context("writing archive manifest")?;
    for name in kind.package_files() {
        writer
            .start_file(name, options)
            .with_context(|| format!("starting archive entry {name}"))?;
        writer
            .write_all(
                files
                    .get(name)
                    .expect("required package file was loaded")
                    .as_ref(),
            )
            .with_context(|| format!("writing archive entry {name}"))?;
    }
    writer.finish().context("completing trace package archive")
}

fn archive_capacity(package_size: u64, manifest_size: u64) -> Result<u64> {
    if package_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES || manifest_size > MAX_ARCHIVE_MANIFEST_BYTES {
        bail!("trace package archive exceeds the on-wire size limit");
    }
    let capacity = package_size
        .checked_add(manifest_size)
        .and_then(|size| size.checked_add(MAX_ZIP_CONTAINER_BYTES))
        .ok_or_else(|| anyhow!("trace package size overflow"))?;
    if capacity > MAX_ARCHIVE_WIRE_BYTES {
        bail!("trace package archive exceeds the on-wire size limit");
    }
    Ok(capacity)
}

/// Parses and validates all `.llmtrace` entries in memory without creating an
/// attacker-controlled path.
pub fn read_trace_package_archive(bytes: &[u8]) -> Result<ValidatedTracePackageArchive> {
    if bytes.len() as u64 > MAX_ARCHIVE_WIRE_BYTES {
        bail!("trace package archive exceeds the on-wire size limit");
    }
    if !bytes.starts_with(b"PK\x03\x04") {
        bail!("trace package archive does not start at the canonical ZIP offset");
    }
    read_validated_archive(bytes)
}

fn read_validated_archive(bytes: &[u8]) -> Result<ValidatedTracePackageArchive> {
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).context("parsing trace package archive")?;
    let expected_count = PACKAGE_FILES.len() + 1;
    if archive.len() != expected_count {
        bail!("archive must contain exactly {expected_count} entries");
    }
    // The first package entry names the evidence kind; every later check is
    // then made against that kind's exact entry set and format.
    let kind = {
        let entry = archive
            .by_index(1)
            .context("reading the trace package evidence entry")?;
        EvidenceKind::from_evidence_entry(entry.name())
            .ok_or_else(|| anyhow!("archive entry ordering is not canonical"))?
    };
    let package_files = kind.package_files();

    let allowed = allowed_archive_entries(kind);
    let mut seen = BTreeSet::new();
    let mut entries = BTreeMap::new();
    let mut total_size = 0u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("reading ZIP entry {index}"))?;
        let name = entry.name().to_owned();
        let expected_name = if index == 0 {
            ARCHIVE_MANIFEST_PATH
        } else {
            package_files[index - 1]
        };
        if name != expected_name {
            bail!("archive entry ordering is not canonical");
        }
        if entry.enclosed_name().as_deref() != Some(Path::new(&name))
            || !allowed.contains(name.as_str())
        {
            bail!("archive contains an invalid or undeclared path: {name}");
        }
        if !seen.insert(name.clone()) {
            bail!("archive contains a duplicate entry: {name}");
        }
        if entry.encrypted() || !entry.is_file() {
            bail!("archive entry must be an unencrypted regular file: {name}");
        }
        if entry.compression() != CompressionMethod::Stored
            || entry.last_modified() != Some(DateTime::default())
            || entry.unix_mode().map(|mode| mode & 0o777) != Some(0o644)
        {
            bail!("archive entry metadata is not canonical: {name}");
        }
        let limit = if name == ARCHIVE_MANIFEST_PATH {
            MAX_ARCHIVE_MANIFEST_BYTES
        } else {
            MAX_ARCHIVE_UNCOMPRESSED_BYTES
        };
        if entry.size() > limit {
            bail!("archive entry exceeds its size limit: {name}");
        }
        total_size = total_size
            .checked_add(entry.size())
            .ok_or_else(|| anyhow!("archive size overflow"))?;
        if total_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES + MAX_ARCHIVE_MANIFEST_BYTES {
            bail!("archive exceeds the total uncompressed size limit");
        }
        let mut data = Vec::with_capacity(entry.size() as usize);
        entry
            .by_ref()
            .take(limit + 1)
            .read_to_end(&mut data)
            .with_context(|| format!("reading archive entry {name}"))?;
        if data.len() as u64 != entry.size() {
            bail!("archive entry size did not match its ZIP metadata: {name}");
        }
        entries.insert(name, data);
    }
    if seen != allowed.into_iter().map(str::to_owned).collect() {
        bail!("archive does not contain the exact required entry set");
    }

    let manifest: TracePackageArchiveManifest = serde_json::from_slice(
        entries
            .get(ARCHIVE_MANIFEST_PATH)
            .expect("validated archive contains its manifest"),
    )
    .context("parsing archive manifest")?;
    if manifest.format != TRACE_PACKAGE_FORMAT || manifest.package_format != kind.evidence_format()
    {
        bail!("unsupported trace package archive format");
    }
    if manifest.files.len() != package_files.len() {
        bail!("archive manifest does not declare the exact package file set");
    }
    for (declared, expected_name) in manifest.files.iter().zip(package_files) {
        if declared.path != expected_name {
            bail!("archive manifest file ordering or path is invalid");
        }
        let data = entries
            .get(expected_name)
            .expect("validated archive contains every package file");
        if declared.size_bytes != data.len() as u64 || declared.sha256 != sha256_hex(data) {
            bail!("archive file hash or size mismatch: {expected_name}");
        }
    }
    if manifest.package_sha256 != package_digest(kind, &manifest.files)? {
        bail!("archive package hash mismatch");
    }
    require_package_format(
        kind,
        entries
            .get("manifest.json")
            .expect("validated archive contains package manifest"),
    )?;
    let manifest_bytes = serde_json::to_vec(&manifest).context("encoding archive manifest")?;
    let comparison = write_trace_package_archive(
        kind,
        &manifest_bytes,
        &entries,
        CanonicalComparisonWriter::new(bytes),
    )?;
    if !comparison.matches_expected() {
        bail!("archive ZIP container is not canonical");
    }
    entries.remove(ARCHIVE_MANIFEST_PATH);
    Ok(ValidatedTracePackageArchive {
        manifest,
        kind,
        files: entries,
    })
}

/// A seekable ZIP destination that compares every canonical write with the
/// uploaded bytes. This preserves byte-for-byte validation without allocating
/// a second near-limit archive beside the decoded entries.
struct CanonicalComparisonWriter<'a> {
    expected: &'a [u8],
    position: u64,
    max_written: u64,
    structurally_valid: bool,
    mismatches: BTreeSet<u64>,
}

impl<'a> CanonicalComparisonWriter<'a> {
    fn new(expected: &'a [u8]) -> Self {
        Self {
            expected,
            position: 0,
            max_written: 0,
            structurally_valid: true,
            mismatches: BTreeSet::new(),
        }
    }

    fn matches_expected(&self) -> bool {
        self.structurally_valid
            && self.mismatches.is_empty()
            && self.max_written == self.expected.len() as u64
    }
}

impl Write for CanonicalComparisonWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let start = usize::try_from(self.position).ok();
        let end = self.position.checked_add(buffer.len() as u64);
        if self.position > self.max_written {
            self.structurally_valid = false;
        }
        match (start, end.and_then(|end| usize::try_from(end).ok())) {
            (Some(start), Some(end)) => {
                let Some(expected) = self.expected.get(start..end) else {
                    self.structurally_valid = false;
                    self.position = end as u64;
                    self.max_written = self.max_written.max(self.position);
                    return Ok(buffer.len());
                };
                if expected == buffer {
                    let corrected = self
                        .mismatches
                        .range(self.position..self.position + buffer.len() as u64)
                        .copied()
                        .collect::<Vec<_>>();
                    for position in corrected {
                        self.mismatches.remove(&position);
                    }
                } else {
                    for (offset, (actual, expected)) in buffer.iter().zip(expected).enumerate() {
                        let position = self.position + offset as u64;
                        if actual == expected {
                            self.mismatches.remove(&position);
                        } else {
                            self.mismatches.insert(position);
                            if self.mismatches.len() > MAX_REWRITTEN_COMPARISON_BYTES {
                                // Canonical ZIP creation only rewrites bounded
                                // local-header fields. A larger mismatch cannot
                                // become canonical later and must not grow with
                                // attacker-controlled archive size.
                                self.structurally_valid = false;
                                self.mismatches.clear();
                                break;
                            }
                        }
                    }
                }
            }
            _ => self.structurally_valid = false,
        }
        self.position = end.unwrap_or(u64::MAX);
        self.max_written = self.max_written.max(self.position);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for CanonicalComparisonWriter<'_> {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let next = match position {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::End(offset) => self.expected.len() as i128 + i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
        };
        self.position = u64::try_from(next).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid ZIP seek")
        })?;
        Ok(self.position)
    }
}

fn require_plain_directory(package: &Path) -> Result<()> {
    if package
        .extension()
        .is_some_and(|extension| extension == "llmcapture" || extension == "llmbundle")
    {
        bail!("encrypted capture files cannot be shared; notarize the capture first");
    }
    let metadata = fs::symlink_metadata(package)
        .with_context(|| format!("reading trace package {}", package.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "trace package builder expects one package directory: {}",
            package.display()
        );
    }
    Ok(())
}

fn require_exact_package_entries(package: &Path) -> Result<EvidenceKind> {
    let kind = if package
        .join(EvidenceKind::Witnessed.evidence_entry())
        .exists()
    {
        EvidenceKind::Witnessed
    } else {
        EvidenceKind::Notarized
    };
    let allowed = kind.package_files().into_iter().collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for entry in fs::read_dir(package)
        .with_context(|| format!("reading trace package {}", package.display()))?
    {
        let entry = entry.context("reading trace package directory entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("trace package contains a non-UTF-8 file name"))?;
        if !allowed.contains(name.as_str()) {
            bail!("trace package contains an undeclared entry: {name}");
        }
        actual.insert(name);
    }
    if actual != allowed.into_iter().map(str::to_owned).collect() {
        bail!("trace package does not contain the exact required file set");
    }
    Ok(kind)
}

fn require_package_format(kind: EvidenceKind, bytes: &[u8]) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("parsing verified package manifest")?;
    if value.get("format").and_then(serde_json::Value::as_str) != Some(kind.evidence_format()) {
        bail!("unsupported verified trace package format");
    }
    Ok(())
}

fn package_digest(kind: EvidenceKind, files: &[ArchiveFile]) -> Result<String> {
    let canonical = serde_json::to_vec(&PackageDigest {
        format: kind.evidence_format(),
        files,
    })
    .context("encoding package digest input")?;
    Ok(sha256_hex(&canonical))
}

fn allowed_archive_entries(kind: EvidenceKind) -> BTreeSet<&'static str> {
    std::iter::once(ARCHIVE_MANIFEST_PATH)
        .chain(kind.package_files())
        .collect()
}

fn deterministic_options() -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(DateTime::default())
        .unix_permissions(0o644)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("notary-archive-{name}-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_files(kind: EvidenceKind, format: &str) -> BTreeMap<String, Vec<u8>> {
        kind.package_files()
            .into_iter()
            .map(|name| {
                let bytes = if name == "manifest.json" {
                    format!(r#"{{"format":"{format}"}}"#).into_bytes()
                } else {
                    format!("fixture:{name}").into_bytes()
                };
                (name.to_owned(), bytes)
            })
            .collect()
    }

    fn build(kind: EvidenceKind, files: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>> {
        build_trace_package_archive_from_entries(TracePackageArchiveEntries {
            kind,
            evidence: &files[kind.evidence_entry()],
            manifest_json: &files["manifest.json"],
            request_disclosed_http: &files["request.disclosed.http"],
            response_disclosed_http: &files["response.disclosed.http"],
            trace_otlp_json: &files["trace.otlp.json"],
        })
    }

    fn fixture_archive_of(kind: EvidenceKind) -> Vec<u8> {
        build(kind, &fixture_files(kind, kind.evidence_format())).unwrap()
    }

    fn fixture_archive() -> Vec<u8> {
        fixture_archive_of(EvidenceKind::Notarized)
    }

    fn fixture_package() -> TestDir {
        let directory = TestDir::new("package");
        for (name, bytes) in fixture_files(EvidenceKind::Notarized, TRACE_EVIDENCE_FORMAT) {
            fs::write(directory.0.join(name), bytes).unwrap();
        }
        directory
    }

    fn rewrite_archive(entries: Vec<(String, Vec<u8>, bool)>) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, bytes, symlink) in entries {
            if symlink {
                writer
                    .add_symlink(
                        name,
                        String::from_utf8(bytes).unwrap(),
                        deterministic_options(),
                    )
                    .unwrap();
            } else {
                writer.start_file(name, deterministic_options()).unwrap();
                writer.write_all(&bytes).unwrap();
            }
        }
        writer.finish().unwrap().into_inner()
    }

    fn archive_entries(bytes: &[u8]) -> Vec<(String, Vec<u8>, bool)> {
        let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
        (0..archive.len())
            .map(|index| {
                let mut entry = archive.by_index(index).unwrap();
                let mut data = Vec::new();
                entry.read_to_end(&mut data).unwrap();
                (entry.name().to_owned(), data, false)
            })
            .collect()
    }

    #[test]
    fn archive_is_reproducible_and_reads_back_exact_files() {
        let first = fixture_archive();
        assert_eq!(first, fixture_archive());
        let archive = read_trace_package_archive(&first).unwrap();
        assert_eq!(archive.manifest.format, TRACE_PACKAGE_FORMAT);
        assert_eq!(
            archive.into_files(),
            fixture_files(EvidenceKind::Notarized, TRACE_EVIDENCE_FORMAT)
        );
    }

    #[test]
    fn witnessed_archive_round_trips_with_its_own_entry_set_and_format() {
        let bytes = fixture_archive_of(EvidenceKind::Witnessed);
        let archive = read_trace_package_archive(&bytes).unwrap();
        assert_eq!(archive.evidence_kind(), EvidenceKind::Witnessed);
        assert_eq!(archive.manifest.package_format, WITNESS_EVIDENCE_FORMAT);
        assert!(archive.file("evidence.witness").is_ok());
        assert!(archive.file("evidence.tlsn").is_err());
    }

    #[test]
    fn evidence_entry_and_format_must_name_the_same_kind() {
        // A Witnessed entry set whose manifests claim the Notarized format
        // must not validate as either kind.
        let mixed = fixture_files(EvidenceKind::Witnessed, TRACE_EVIDENCE_FORMAT);
        assert!(build(EvidenceKind::Witnessed, &mixed).is_err());

        let notarized = fixture_archive();
        let renamed = archive_entries(&notarized)
            .into_iter()
            .map(|(name, bytes, symlink)| {
                let name = if name == "evidence.tlsn" {
                    "evidence.witness".to_owned()
                } else {
                    name
                };
                (name, bytes, symlink)
            })
            .collect();
        assert!(read_trace_package_archive(&rewrite_archive(renamed)).is_err());
    }

    #[test]
    fn in_memory_and_directory_builders_produce_identical_bytes() {
        let package = fixture_package();

        let from_directory = build_trace_package_archive(&package.0).unwrap();
        assert_eq!(fixture_archive(), from_directory);
    }

    #[test]
    fn archive_wire_limit_accepts_the_exact_payload_boundary() {
        assert_eq!(
            archive_capacity(MAX_ARCHIVE_UNCOMPRESSED_BYTES, MAX_ARCHIVE_MANIFEST_BYTES).unwrap(),
            MAX_ARCHIVE_WIRE_BYTES
        );
        assert!(
            archive_capacity(
                MAX_ARCHIVE_UNCOMPRESSED_BYTES + 1,
                MAX_ARCHIVE_MANIFEST_BYTES,
            )
            .is_err()
        );
        assert!(
            archive_capacity(
                MAX_ARCHIVE_UNCOMPRESSED_BYTES,
                MAX_ARCHIVE_MANIFEST_BYTES + 1,
            )
            .is_err()
        );
    }

    #[test]
    fn canonical_comparison_mismatch_state_is_container_bounded() {
        let expected = vec![0; MAX_REWRITTEN_COMPARISON_BYTES + 1];
        let actual = vec![1; expected.len()];
        let mut comparison = CanonicalComparisonWriter::new(&expected);
        comparison.write_all(&actual).unwrap();
        assert!(!comparison.structurally_valid);
        assert!(comparison.mismatches.is_empty());
        assert!(!comparison.matches_expected());
    }

    #[test]
    fn package_builder_rejects_undeclared_entries_and_symlinks() {
        let package = fixture_package();
        fs::write(package.0.join("extra.txt"), b"no").unwrap();
        assert!(build_trace_package_archive(&package.0).is_err());

        #[cfg(unix)]
        {
            let package = fixture_package();
            fs::remove_file(package.0.join("trace.otlp.json")).unwrap();
            std::os::unix::fs::symlink("manifest.json", package.0.join("trace.otlp.json")).unwrap();
            assert!(build_trace_package_archive(&package.0).is_err());
        }
    }

    #[test]
    fn archive_rejects_traversal_absolute_duplicates_symlinks_and_undeclared_files() {
        let valid = fixture_archive();

        for bad_name in ["../trace.otlp.json", "/trace.otlp.json", "extra.txt"] {
            let mut entries = archive_entries(&valid);
            entries[5].0 = bad_name.to_owned();
            assert!(read_trace_package_archive(&rewrite_archive(entries)).is_err());
        }

        // zip's writer refuses duplicate names, so mutate the equal-length
        // local and central-directory names to model hostile input.
        let mut duplicate = valid.clone();
        let mut replacements = 0;
        for index in 0..duplicate.len().saturating_sub(46) {
            let name_start = if duplicate[index..].starts_with(b"PK\x03\x04") {
                Some(index + 30)
            } else if duplicate[index..].starts_with(b"PK\x01\x02") {
                Some(index + 46)
            } else {
                None
            };
            if let Some(name_start) = name_start
                && duplicate.get(name_start..name_start + b"evidence.tlsn".len())
                    == Some(b"evidence.tlsn")
            {
                duplicate[name_start..name_start + b"manifest.json".len()]
                    .copy_from_slice(b"manifest.json");
                replacements += 1;
            }
        }
        assert_eq!(replacements, 2);
        assert!(read_trace_package_archive(&duplicate).is_err());

        let mut symlink = archive_entries(&valid);
        symlink[5] = (
            "trace.otlp.json".to_owned(),
            b"manifest.json".to_vec(),
            true,
        );
        assert!(read_trace_package_archive(&rewrite_archive(symlink)).is_err());
    }

    #[test]
    fn archive_rejects_file_and_package_hash_mismatches() {
        let valid = fixture_archive();

        let mut file_mismatch = archive_entries(&valid);
        file_mismatch[5].1.push(b'!');
        assert!(read_trace_package_archive(&rewrite_archive(file_mismatch)).is_err());

        let mut package_mismatch = archive_entries(&valid);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&package_mismatch[0].1).unwrap();
        manifest["package_sha256"] = serde_json::Value::String("0".repeat(64));
        package_mismatch[0].1 = serde_json::to_vec(&manifest).unwrap();
        assert!(read_trace_package_archive(&rewrite_archive(package_mismatch)).is_err());
    }

    #[test]
    fn archive_rejects_noncanonical_outer_zip_bytes() {
        let valid = fixture_archive();

        let mut prefixed = b"not-part-of-the-zip".to_vec();
        prefixed.extend_from_slice(&valid);
        assert!(ZipArchive::new(Cursor::new(&prefixed)).is_ok());
        assert!(read_trace_package_archive(&prefixed).is_err());

        let mut trailing = valid.clone();
        trailing.extend_from_slice(b"not-part-of-the-zip");
        assert!(read_trace_package_archive(&trailing).is_err());

        let mut entries = archive_entries(&valid);
        let manifest: serde_json::Value = serde_json::from_slice(&entries[0].1).unwrap();
        entries[0].1 = serde_json::to_vec_pretty(&manifest).unwrap();
        assert!(read_trace_package_archive(&rewrite_archive(entries)).is_err());
    }
}
