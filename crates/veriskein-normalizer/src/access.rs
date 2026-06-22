const O_WRONLY: u32 = 1;
const O_RDWR: u32 = 2;
const O_ACCMODE: u32 = 3;
const O_CREAT: u32 = 64;
const O_TRUNC: u32 = 512;
const O_APPEND: u32 = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAccessMode {
    pub is_read: bool,
    pub is_write: bool,
}

pub fn file_access_mode(flags: u32) -> FileAccessMode {
    let access_mode = flags & O_ACCMODE;
    FileAccessMode {
        is_read: access_mode == 0 || access_mode == O_RDWR,
        is_write: access_mode == O_WRONLY
            || access_mode == O_RDWR
            || flags & (O_CREAT | O_TRUNC | O_APPEND) != 0,
    }
}
