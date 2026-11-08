use std::io;
use tokio::net::TcpStream;

/// Отправляет один байт как OOB (urgent data).
pub fn send_oob(stream: &TcpStream, byte: u8) -> io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let fd = stream.as_raw_fd();
        // SAFETY: `fd` взят из живого `TcpStream`, буфер валиден в течение вызова,
        // а libc::send не удерживает указатель после возврата.
        let sent = unsafe {
            libc::send(
                fd,
                &byte as *const u8 as *const libc::c_void,
                1,
                libc::MSG_OOB | libc::MSG_DONTWAIT,
            )
        };

        if sent < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        }
    }

    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{send, MSG_OOB, SOCKET_ERROR};

        let socket = stream.as_raw_socket() as usize;
        // SAFETY: сокет принадлежит живому `TcpStream`, буфер валиден на время вызова,
        // `MSG_OOB` отправляет один байт без удержания ссылки.
        let sent = unsafe { send(socket, &byte as *const u8, 1, MSG_OOB) };

        if sent == SOCKET_ERROR {
            Err(io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (stream, byte);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "OOB не поддерживается на этой платформе",
        ))
    }
}
