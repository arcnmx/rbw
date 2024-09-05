use anyhow::{bail, Context as _};
use rbw::cipher::Cipher;
use std::io::Read as _;
use crate::sock::Sock;

pub fn register() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Register)
}

pub fn login() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Login)
}

pub fn unlock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Unlock)
}

pub fn unlocked() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::CheckLock)
}

pub fn sync() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Sync)
}

pub fn lock() -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::Lock)
}

pub fn quit() -> anyhow::Result<()> {
    match Sock::connect() {
        Ok(mut sock) => {
            let pidfile = rbw::dirs::pid_file();
            let mut pid = String::new();
            std::fs::File::open(pidfile)?.read_to_string(&mut pid)?;
            let Some(pid) =
                rustix::process::Pid::from_raw(pid.trim_end().parse()?)
            else {
                bail!("failed to read pid from pidfile");
            };
            sock.send(&rbw::protocol::Request {
                tty: rustix::termios::ttyname(std::io::stdin(), vec![])
                    .ok()
                    .and_then(|p| {
                        p.to_str().map(std::string::ToString::to_string).ok()
                    }),
                action: rbw::protocol::Action::Quit,
            })?;
            wait_for_exit(pid);
            Ok(())
        }
        Err(e) => match e.kind() {
            // if the socket doesn't exist, or the socket exists but nothing
            // is listening on it, the agent must already be not running
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(e.into()),
        },
    }
}

impl Cipher for Sock {
    fn decrypt(
        &mut self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        self.send(&rbw::protocol::Request {
            tty: rustix::termios::ttyname(std::io::stdin(), vec![])
                .ok()
                .and_then(|p| {
                    p.to_str().map(std::string::ToString::to_string).ok()
                }),
            action: rbw::protocol::Action::Decrypt {
                cipherstring: cipherstring.to_string(),
                entry_key: entry_key.map(std::string::ToString::to_string),
                org_id: org_id.map(std::string::ToString::to_string),
            },
        })?;

        let res = self.recv()?;
        match res {
            rbw::protocol::Response::Decrypt { plaintext } => Ok(plaintext),
            rbw::protocol::Response::Error { error } => {
                Err(anyhow::anyhow!("failed to decrypt: {}", error))
            }
            _ => Err(anyhow::anyhow!("unexpected message: {:?}", res)),
        }
    }

    fn encrypt(
        &mut self,
        plaintext: &str,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        self.send(&rbw::protocol::Request {
            tty: rustix::termios::ttyname(std::io::stdin(), vec![])
                .ok()
                .and_then(|p| {
                    p.to_str().map(std::string::ToString::to_string).ok()
                }),
            action: rbw::protocol::Action::Encrypt {
                plaintext: plaintext.to_string(),
                org_id: org_id.map(std::string::ToString::to_string),
            },
        })?;

        let res = self.recv()?;
        match res {
            rbw::protocol::Response::Encrypt { cipherstring } => Ok(cipherstring),
            rbw::protocol::Response::Error { error } => {
                Err(anyhow::anyhow!("failed to encrypt: {}", error))
            }
            _ => Err(anyhow::anyhow!("unexpected message: {:?}", res)),
        }
    }
}

pub fn decrypt(
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.decrypt(cipherstring, entry_key, org_id)
}

pub fn encrypt(
    plaintext: &str,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    let mut sock = connect()?;
    sock.encrypt(plaintext, org_id)
}

pub fn clipboard_store(text: &str) -> anyhow::Result<()> {
    simple_action(rbw::protocol::Action::ClipboardStore {
        text: text.to_string(),
    })
}

pub fn version() -> anyhow::Result<u32> {
    let mut sock = connect()?;
    sock.send(&rbw::protocol::Request {
        tty: rustix::termios::ttyname(std::io::stdin(), vec![])
            .ok()
            .and_then(|p| {
                p.to_str().map(std::string::ToString::to_string).ok()
            }),
        action: rbw::protocol::Action::Version,
    })?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Version { version } => Ok(version),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("failed to get version: {}", error))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {:?}", res)),
    }
}

fn simple_action(action: rbw::protocol::Action) -> anyhow::Result<()> {
    let mut sock = connect()?;

    sock.send(&rbw::protocol::Request {
        tty: rustix::termios::ttyname(std::io::stdin(), vec![])
            .ok()
            .and_then(|p| {
                p.to_str().map(std::string::ToString::to_string).ok()
            }),
        action,
    })?;

    let res = sock.recv()?;
    match res {
        rbw::protocol::Response::Ack => Ok(()),
        rbw::protocol::Response::Error { error } => {
            Err(anyhow::anyhow!("{}", error))
        }
        _ => Err(anyhow::anyhow!("unexpected message: {:?}", res)),
    }
}

fn connect() -> anyhow::Result<Sock> {
    Sock::connect().with_context(|| {
        let log = rbw::dirs::agent_stderr_file();
        format!(
            "failed to connect to rbw-agent \
            (this often means that the agent failed to start; \
            check {} for agent logs)",
            log.display()
        )
    })
}

fn wait_for_exit(pid: rustix::process::Pid) {
    loop {
        if rustix::process::test_kill_process(pid).is_err() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

pub struct Agent;

impl Cipher for Agent {
    fn decrypt(
        &mut self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        decrypt(cipherstring, entry_key, org_id)
    }

    fn encrypt(
        &mut self,
        plaintext: &str,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        encrypt(plaintext, org_id)
    }
}
