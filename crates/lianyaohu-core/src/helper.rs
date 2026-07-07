use crate::{Result, err};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::{io, mem, ptr};

pub const SOCKET_PATH: &str = "/var/run/lianyaohu-helper.sock";
pub const DAEMON_LABEL: &str = "io.github.madeye.lianyaohu.helper";

pub struct PFHelperClient {
    socket_path: String,
}

impl PFHelperClient {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub fn install(&self, interface_name: &str) -> Result<()> {
        let response = self.send(&format!("install {interface_name}\n"))?;
        if response.ok {
            Ok(())
        } else {
            Err(err(response.message))
        }
    }

    pub fn uninstall(&self) -> Result<()> {
        let response = self.send("uninstall\n")?;
        if response.ok {
            Ok(())
        } else {
            Err(err(response.message))
        }
    }

    pub fn status(&self) -> Result<HelperResponse> {
        self.send("status\n")
    }

    pub fn run_session(&self, interface_name: &str, spec_path: &Path) -> Result<i32> {
        let spec_path = spec_path
            .to_str()
            .ok_or_else(|| err("launch spec path is not valid UTF-8"))?;
        if spec_path.contains(char::is_whitespace) {
            return Err(err("launch spec path cannot contain whitespace"));
        }
        let response = self.send_with_fds(
            &format!("run {interface_name} {spec_path}\n"),
            &[libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO],
        )?;
        if !response.ok {
            return Err(err(response.message));
        }
        let Some(code) = response
            .message
            .strip_prefix("exit ")
            .and_then(|value| value.parse::<i32>().ok())
        else {
            return Err(err(format!(
                "invalid helper run response: {:?}",
                response.message
            )));
        };
        Ok(code)
    }

    fn send(&self, request: &str) -> Result<HelperResponse> {
        let socket_path = if self.socket_path.is_empty() {
            SOCKET_PATH
        } else {
            &self.socket_path
        };
        let mut stream = UnixStream::connect(socket_path)?;
        stream.write_all(request.as_bytes())?;
        stream.shutdown(Shutdown::Write)?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        parse_response(&response)
    }

    fn send_with_fds(&self, request: &str, fds: &[RawFd]) -> Result<HelperResponse> {
        let socket_path = if self.socket_path.is_empty() {
            SOCKET_PATH
        } else {
            &self.socket_path
        };
        let mut stream = UnixStream::connect(socket_path)?;
        send_message_with_fds(&stream, request.as_bytes(), fds)?;
        stream.shutdown(Shutdown::Write)?;

        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        parse_response(&response)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct HelperResponse {
    pub ok: bool,
    pub message: String,
}

pub fn parse_response(response: &str) -> Result<HelperResponse> {
    if let Some(message) = response.strip_prefix("ok ") {
        return Ok(HelperResponse {
            ok: true,
            message: message.trim_end().to_string(),
        });
    }
    if let Some(message) = response.strip_prefix("error ") {
        return Ok(HelperResponse {
            ok: false,
            message: message.trim_end().to_string(),
        });
    }
    Err(err(format!("invalid helper response: {response:?}")))
}

pub fn parse_request(line: &str) -> Result<HelperRequest> {
    let trimmed = line.trim();
    if trimmed == "uninstall" {
        return Ok(HelperRequest::Uninstall);
    }
    if trimmed == "status" {
        return Ok(HelperRequest::Status);
    }
    if let Some(interface_name) = trimmed.strip_prefix("install ") {
        if interface_name.is_empty() || interface_name.contains(char::is_whitespace) {
            return Err(err("invalid helper install interface"));
        }
        return Ok(HelperRequest::Install {
            interface_name: interface_name.to_string(),
        });
    }
    if let Some(rest) = trimmed.strip_prefix("run ") {
        let (interface_name, spec_path) = rest
            .split_once(' ')
            .ok_or_else(|| err("invalid helper run request"))?;
        if interface_name.is_empty()
            || interface_name.contains(char::is_whitespace)
            || spec_path.is_empty()
            || spec_path.contains(char::is_whitespace)
        {
            return Err(err("invalid helper run request"));
        }
        return Ok(HelperRequest::Run {
            interface_name: interface_name.to_string(),
            spec_path: spec_path.to_string(),
        });
    }
    Err(err(format!("invalid helper request: {trimmed:?}")))
}

#[derive(Debug, Eq, PartialEq)]
pub enum HelperRequest {
    Install {
        interface_name: String,
    },
    Run {
        interface_name: String,
        spec_path: String,
    },
    Uninstall,
    Status,
}

impl Default for PFHelperClient {
    fn default() -> Self {
        Self {
            socket_path: SOCKET_PATH.to_string(),
        }
    }
}

pub struct ReceivedMessage {
    pub message: String,
    pub fds: Vec<OwnedFd>,
}

pub fn send_message_with_fds(stream: &UnixStream, bytes: &[u8], fds: &[RawFd]) -> io::Result<()> {
    if fds.is_empty() {
        let mut stream = stream;
        stream.write_all(bytes)?;
        return Ok(());
    }

    let fd_bytes = mem::size_of_val(fds);
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as _) as usize }];
    let mut msg = unsafe { mem::zeroed::<libc::msghdr>() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;

    unsafe {
        let header = libc::CMSG_FIRSTHDR(&msg);
        if header.is_null() {
            return Err(io::Error::other("missing control message header"));
        }
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(fd_bytes as _) as _;
        ptr::copy_nonoverlapping(
            fds.as_ptr().cast::<u8>(),
            libc::CMSG_DATA(header).cast::<u8>(),
            fd_bytes,
        );

        let sent = libc::sendmsg(stream.as_raw_fd(), &msg, 0);
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial helper request send",
            ));
        }
    }

    Ok(())
}

pub fn receive_message_with_fds(
    stream: &UnixStream,
    max_bytes: usize,
    max_fds: usize,
) -> io::Result<ReceivedMessage> {
    let mut bytes = vec![0u8; max_bytes];
    let fd_bytes = max_fds * mem::size_of::<RawFd>();
    let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(fd_bytes as _) as usize }];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let mut msg = unsafe { mem::zeroed::<libc::msghdr>() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;

    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other(
            "truncated file descriptors in helper request",
        ));
    }
    bytes.truncate(received as usize);

    let mut fds = Vec::new();
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                if (*header).cmsg_len < libc::CMSG_LEN(0) as _ {
                    return Err(io::Error::other("malformed helper control message"));
                }
                let data_len = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let count = data_len / mem::size_of::<RawFd>();
                if fds.len() + count > max_fds {
                    return Err(io::Error::other(
                        "too many file descriptors in helper request",
                    ));
                }
                let data = libc::CMSG_DATA(header).cast::<RawFd>();
                for index in 0..count {
                    fds.push(OwnedFd::from_raw_fd(*data.add(index)));
                }
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
    }

    let message = String::from_utf8(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(ReceivedMessage { message, fds })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn parses_helper_requests() {
        assert_eq!(
            parse_request("install utun5\n").unwrap(),
            HelperRequest::Install {
                interface_name: "utun5".to_string()
            }
        );
        assert_eq!(
            parse_request("uninstall\n").unwrap(),
            HelperRequest::Uninstall
        );
        assert_eq!(parse_request("status\n").unwrap(), HelperRequest::Status);
        assert_eq!(
            parse_request("run utun5 /tmp/lianyaohu-launch.json\n").unwrap(),
            HelperRequest::Run {
                interface_name: "utun5".to_string(),
                spec_path: "/tmp/lianyaohu-launch.json".to_string()
            }
        );
        assert!(parse_request("install en0").is_ok());
        assert!(parse_request("install utun 5").is_err());
        assert!(parse_request("run utun5 /tmp/has space.json").is_err());
    }

    #[test]
    fn parses_helper_responses() {
        assert_eq!(
            parse_response("ok installed\n").unwrap(),
            HelperResponse {
                ok: true,
                message: "installed".to_string()
            }
        );
        assert_eq!(
            parse_response("error denied\n").unwrap(),
            HelperResponse {
                ok: false,
                message: "denied".to_string()
            }
        );
    }

    #[test]
    fn sends_and_receives_file_descriptors() {
        let (left, right) = UnixStream::pair().unwrap();
        let mut file = tempfile_file();
        file.write_all(b"fd-ok").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();

        send_message_with_fds(&left, b"run test\n", &[file.as_raw_fd()]).unwrap();
        let received = receive_message_with_fds(&right, 1024, 1).unwrap();

        assert_eq!(received.message, "run test\n");
        assert_eq!(received.fds.len(), 1);
        let mut received_file = File::from(received.fds.into_iter().next().unwrap());
        let mut contents = String::new();
        received_file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "fd-ok");
    }

    fn tempfile_file() -> File {
        let mut path = std::env::temp_dir();
        path.push(format!("lianyaohu-helper-fd-test-{}", std::process::id()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let _ = std::fs::remove_file(path);
        file
    }
}
