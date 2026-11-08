use std::io;
use std::path::Path;
use std::process::Stdio;

use tokio::process::{Child, Command};

/// Описание внешнего движка обхода DPI (ciadpi/byedpi или winws/zapret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalEngine {
    pub program: String,
    pub args: Vec<String>,
}

impl ExternalEngine {
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
        }
    }

    /// Ищет `ciadpi.exe`/`winws.exe` рядом с указанным каталогом.
    pub fn detect(directory: &Path) -> Option<Self> {
        const CANDIDATES: &[(&str, &[&str])] = &[
            ("ciadpi.exe", &["--socks", "127.0.0.1:1080"]),
            ("winws.exe", &[]),
        ];

        for (name, args) in CANDIDATES {
            let path = directory.join(name);
            if path.is_file() {
                return Some(Self::new(
                    path.to_string_lossy().to_string(),
                    args.iter().map(|arg| (*arg).to_string()).collect(),
                ));
            }
        }

        None
    }

    /// Запускает движок как дочерний процесс (завершается вместе с владельцем).
    pub fn spawn(&self) -> io::Result<Child> {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }

        command.spawn()
    }
}
