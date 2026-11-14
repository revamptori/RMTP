//! Atomic filesystem operations for the persistent queue.
//!
//! All writes go to a temporary file in the same directory and are renamed
//! into place, guaranteeing crash consistency (no partial messages).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Write `contents` to `path` atomically.
///
/// Writes to `path.tmp.<pid>` in the same directory, fsyncs, then renames.
pub fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{}.tmp.{}", path.file_name().unwrap_or_default().to_string_lossy(), std::process::id()));
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(contents)?;
        file.flush()?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    // fsync the directory so the rename is durable.
    let dir_file = fs::File::open(dir)?;
    dir_file.sync_all()?;
    Ok(())
}

/// Append `contents` to `path` atomically (read-modify-write-rename).
pub fn append_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut existing = if path.exists() { fs::read(path)? } else { Vec::new() };
    existing.extend_from_slice(contents);
    write_atomic(path, &existing)
}

/// Read a file's contents.
pub fn read_file(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path)
}

/// Ensure a directory exists, creating parents as needed.
pub fn ensure_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

/// Remove a file if it exists, ignoring "not found" errors.
pub fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// List files in a directory matching a prefix.
pub fn list_files(dir: &Path, prefix: &str) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with(prefix) && !name.ends_with('.tmp') {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn atomic_write_read_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rmtp-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("message.eml");
        let contents = b"From: a@b.c\r\nTo: c@d.e\r\n\r\nbody";
        write_atomic(&path, contents).unwrap();
        let mut got = Vec::new();
        fs::File::open(&path).unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, contents);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_no_leftover_tmp() {
        let dir = std::env::temp_dir().join(format!("rmtp-test2-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m.eml");
        write_atomic(&path, b"x").unwrap();
        let tmp_count = fs::read_dir(&dir).unwrap().filter(|e| e.unwrap().path().extension().map_or(false, |ext| ext == "tmp")).count();
        assert_eq!(tmp_count, 0);
        let _ = fs::remove_dir_all(&dir);
    }
}
