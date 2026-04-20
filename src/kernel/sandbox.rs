use cap_std::ambient_authority;
use cap_std::fs::Dir;
use std::path::{Path, PathBuf};

use super::KernelResult;

pub struct Sandbox {
    dir: Dir,
    root_path: PathBuf,
}

impl Sandbox {
    pub fn open<P: AsRef<Path>>(root: P) -> KernelResult<Self> {
        let root_path = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root_path)?;
        let dir = Dir::open_ambient_dir(&root_path, ambient_authority())?;
        Ok(Self { dir, root_path })
    }

    pub fn dir(&self) -> &Dir {
        &self.dir
    }

    pub fn root_path(&self) -> &Path {
        &self.root_path
    }
}
