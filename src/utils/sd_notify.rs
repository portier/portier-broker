use std::{env, ffi::OsString, io, os::unix::net::UnixDatagram};

// Sends state notifications to systemd.
//
// Based on https://github.com/lnicola/sd-notify (MIT/Apache-2.0)
pub struct SdNotify {
    path: Option<OsString>,
}

impl SdNotify {
    pub fn new() -> Self {
        let path = env::var_os("NOTIFY_SOCKET");
        // TODO: Audit that the environment access only happens in single-threaded code.
        //unsafe { env::remove_var("NOTIFY_SOCKET") };
        Self { path }
    }

    pub fn notify_ready(&self) {
        self.send(b"READY=1\n")
            .expect("Failed to signal ready to the service manager");
    }

    pub fn notify_stopping(&self) {
        if let Err(err) = self.send(b"STOPPING=1\n") {
            log::error!("Failed to signal stopping to the service manager: {err}");
        }
    }

    fn send(&self, msg: &[u8]) -> io::Result<()> {
        let Some(path) = self.path.as_ref() else {
            return Ok(());
        };

        let sock = UnixDatagram::unbound()?;
        let len = sock.send_to(msg, path)?;
        if len != msg.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "incomplete write"));
        }

        Ok(())
    }
}
