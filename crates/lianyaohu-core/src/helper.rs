use crate::{Result, err};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

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
    Err(err(format!("invalid helper request: {trimmed:?}")))
}

#[derive(Debug, Eq, PartialEq)]
pub enum HelperRequest {
    Install { interface_name: String },
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(parse_request("install en0").is_ok());
        assert!(parse_request("install utun 5").is_err());
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
}
