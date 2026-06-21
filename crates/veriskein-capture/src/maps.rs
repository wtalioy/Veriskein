use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryMapping {
    pub path: PathBuf,
    pub dev: u64,
    pub inode: u64,
}

pub trait MapsProvider {
    fn library_mappings(&self, pid: u32) -> Result<Vec<LibraryMapping>>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ProcMapsProvider;

impl MapsProvider for ProcMapsProvider {
    fn library_mappings(&self, pid: u32) -> Result<Vec<LibraryMapping>> {
        let path = PathBuf::from(format!("/proc/{pid}/maps"));
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read process maps {}", path.display()))?;
        Ok(parse_maps(&text))
    }
}

pub(crate) fn parse_maps(text: &str) -> Vec<LibraryMapping> {
    text.lines().filter_map(parse_maps_line).collect()
}

fn parse_maps_line(line: &str) -> Option<LibraryMapping> {
    let mut parts = line.split_whitespace();
    let _range = parts.next()?;
    let _perms = parts.next()?;
    let _offset = parts.next()?;
    let dev = parse_dev(parts.next()?)?;
    let inode = parts.next()?.parse().ok()?;
    let path = parts.next()?;
    if !path.starts_with('/') {
        return None;
    }
    Some(LibraryMapping {
        path: Path::new(path).to_path_buf(),
        dev,
        inode,
    })
}

fn parse_dev(raw: &str) -> Option<u64> {
    let (major, minor) = raw.split_once(':')?;
    let major = u64::from_str_radix(major, 16).ok()?;
    let minor = u64::from_str_radix(minor, 16).ok()?;
    Some((major << 32) | minor)
}

pub(crate) fn is_supported_openssl(mapping: &LibraryMapping) -> bool {
    let Some(name) = mapping.path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.starts_with("libssl.so.3") || name.starts_with("libssl.so.1.1")
}

pub(crate) fn is_known_unsupported_tls(mapping: &LibraryMapping) -> bool {
    let text = mapping.path.to_string_lossy().to_ascii_lowercase();
    text.contains("boringssl")
        || text.contains("rustls")
        || text.contains("libssl.a")
        || text.contains("go-build")
}

#[cfg(test)]
mod tests {
    use super::{is_supported_openssl, parse_maps};

    #[test]
    fn parses_proc_maps_library_rows() {
        let rows = parse_maps(
            "7f00-7f10 r-xp 00000000 08:01 123 /usr/lib/libssl.so.3\n\
             7f10-7f20 r--p 00000000 00:00 0 [heap]\n",
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].inode, 123);
        assert!(is_supported_openssl(&rows[0]));
    }
}
