#![allow(clippy::large_enum_variant)]

use anyhow::Context as _;
use clap::Parser as _;
use rbw::cipher::*;
use std::convert::Infallible;
use std::path::PathBuf;
use std::ffi::OsString;
use std::io::{self, Write as _};
use std::str::FromStr;
use url::Url;

#[derive(Debug, clap::Parser)]
#[command(version, about = "Unofficial Bitwarden CLI")]
struct Opt {
    #[arg(short, long, default_value = "pass")]
    //#[arg(possible_value = "pass", possible_value = "json", possible_value = "debug")]
    format: OutputFormat,
    #[arg(short, long, default_value = "-")]
    password: Password,
    #[arg(short, long)]
    email: Option<String>,
    #[arg(short, long)]
    server: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone)]
pub enum Password {
    Plaintext(String),
    Stdin,
    Pinentry,
    Exec {
        process: PathBuf,
        args: Vec<OsString>,
    },
    File {
        path: PathBuf,
    },
    Gpg {
        path: PathBuf,
        keyid: Option<String>,
    },
}

impl Password {
    fn password_from_bytes<B: IntoIterator<Item=u8>>(bytes: B) -> rbw::locked::Password {
        let mut out = rbw::locked::Vec::new();
        out.extend(bytes.into_iter());
        rbw::locked::Password::new(out)
    }

    fn password_from_read<R: io::Read>(mut read: R) -> io::Result<rbw::locked::Password> {
        let mut out = rbw::locked::Vec::new();
        let mut buf = [0u8; 16]; // TODO: read directly into out
        loop {
            match read.read(&mut buf)? {
                0 => break,
                len =>
                    out.extend(buf[..len].iter().copied()),
            }
            if let Some(newline) = out.data().iter().enumerate().find(|&(_, &c)| c == b'\n').map(|(i, _)| i) {
                // break on the first newline and strip it out
                out.truncate(newline);
                break
            }
        }

        Ok(rbw::locked::Password::new(out))
    }

    async fn read_password(&self) -> Result<rbw::locked::Password, anyhow::Error> {
        match self {
            Password::Plaintext(p) =>
                Ok(Password::password_from_bytes(p.bytes())),
            Password::Exec { process, args } => {
                use std::process::{self, Stdio};
                let mut child = process::Command::new(process)
                    .args(args)
                    .stdin(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .stdout(Stdio::piped())
                    .spawn()?;
                let stdout = child.stdout.as_mut()
                    .ok_or_else(|| anyhow::anyhow!("expected child stdout"))?;

                let res = Password::password_from_read(stdout)?;

                let status = child.wait()?;
                if !status.success() {
                    return Err(if let Some(code) = status.code() {
                        anyhow::anyhow!("{} exited with status code {}", process.display(), code)
                    } else {
                        anyhow::anyhow!("{} did not exit successfully", process.display())
                    })
                }

                Ok(res)
            },
            Password::Gpg { path, keyid } => {
                let process = "gpg".into();
                let mut args = vec![
                    OsString::from("-d"),
                    "--quiet".into(),
                    "--batch".into(),
                    "--yes".into(),
                ];
                if let Some(keyid) = keyid {
                    args.push(OsString::from("--default-key")); // and/or --try-secret-key?
                    args.push(keyid.into());
                }
                args.push(path.into());
                Box::pin(Password::Exec {
                    process,
                    args,
                }.read_password()).await
            },
            Password::Pinentry => {
                let tty = rustix::termios::ttyname(std::io::stdin(), vec![])
                    .ok();
                let res = rbw::pinentry::getpin(
                    &rbw::config::Config::load_async().await?.pinentry,
                    "Bitwarden Master Password",
                    "bitw database unlock",
                    None,
                    tty.as_ref().and_then(|p| p.to_str().ok()),
                    true,
                ).await;
                res.context("failed to read password from pinentry")
                    .map(Into::into)
            },
            Password::Stdin => {
                let stdin = io::stdin();
                if rustix::termios::isatty(&stdin) {
                    eprint!("Master password: ");
                }
                let stdin = stdin.lock();
                Ok(Password::password_from_read(stdin)?)
            },
            Password::File { path } => {
                use std::fs::File;
                let f = File::open(path)?;
                Ok(Password::password_from_read(f)?)
            },
        }
    }
}

impl FromStr for Password {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "-" => Password::Stdin,
            s => match Url::from_str(s) {
                Ok(url) => match url.scheme() {
                    "file" => Password::File {
                        path: PathBuf::from(url.path()),
                    },
                    "pin" => Password::Pinentry,
                    "gpg" => Password::Gpg {
                        path: PathBuf::from(url.path()),
                        keyid: url.query_pairs().find(|&(ref k, _)| k == "keyid").map(|(_, v)| v.into()),
                    },
                    scheme => return Err(anyhow::anyhow!("Unknown password scheme {}", scheme)),
                },
                Err(_) => Password::Plaintext(s.into()),
            },
        })
    }
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Pass,
    Json,
    Debug,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pass" => Ok(OutputFormat::Pass),
            "json" => Ok(OutputFormat::Json),
            "debug" => Ok(OutputFormat::Debug),
            _ => Err(format!("Unsupported output format {}", s)),
        }
    }
}

#[derive(Debug, Clone, clap::ValueEnum)]
// TODO: rename lowercase?
enum Setting {
    Email,
    BaseUrl,
    IdentityUrl,
}

impl FromStr for Setting {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "email" => Ok(Setting::Email),
            "baseurl" => Ok(Setting::BaseUrl),
            "identityurl" => Ok(Setting::IdentityUrl),
            _ => Err(format!("Unsupported setting {}", s)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Field {
    Password,
    Username,
    Notes,
    Custom(String),
}

impl FromStr for Field {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "password" => Field::Password,
            "username" | "login" => Field::Username,
            "notes" => Field::Notes,
            other => Field::Custom(other.into()),
        })
    }
}

#[derive(Debug, clap::Parser)]
#[command(version, about = "Unofficial Bitwarden CLI")]
enum Command {
    #[command(alias = "show")]
    Get {
        query: Needle,
        #[arg(long, short)]
        field: Option<Field>,
    },
    #[command(alias = "ls")]
    List {
        query: Option<String>,
    },
    Config {
        //#[arg(possible_value = "email", possible_value = "baseurl", possible_value = "identityurl")]
        setting: Setting,
        value: String,
    },
    Sync,
    Login,
    Register,
}

impl Command {
    fn subcommand_name(&self) -> &'static str {
        match self {
            Self::Get { .. } => "get",
            Self::List { .. } => "list",
            Self::Config { .. } => "config",
            Self::Sync => "sync",
            Self::Login => "login",
            Self::Register => "register",
        }
    }
}

fn entries<'db: 'a, 'a, C: Cipher + 'a>(crypt: &'a mut C, db: &'db rbw::db::Db) -> impl Iterator<Item=anyhow::Result<(&'db rbw::db::Entry, DecryptedCipher)>> + 'a {
    db.entries.iter().map(move |cipher| decrypt_cipher(&mut *crypt, cipher).map(|entry| ((cipher, entry))))
}

fn find_by_entry<'db, C: Cipher>(mut crypt: C, db: &'db rbw::db::Db, query: &Needle) -> anyhow::Result<Option<(&'db rbw::db::Entry, DecryptedCipher)>> {
    let (folder, needle) = query.split_folder()?;
    let folder = folder.as_ref().map(|f| f.as_str());
    let username = None;

    let entries = entries(&mut crypt, db)
        .filter_map(|res| match res {
            Err(e) => Some(Err(e)),
            Ok((cipher, entry)) if entry.exact_match(&needle, username, folder, folder.is_some(), false) =>
                Some(Ok((cipher, entry))),
            Ok(_) => None,
        });

    let mut res = Ok(());
    for entry in entries {
        match entry {
            Ok(entry) => return Ok(Some(entry)),
            Err(e) => res = Err(e),
        }
    }

    res.map(|()| None)
}

fn output_entry(opt: &Opt, entry: &DecryptedCipher, field_query: &Option<Field>) -> anyhow::Result<()> {
    if let Some(field_query) = field_query {
        match opt.format {
            OutputFormat::Json => // not sure how to handle this?
                unimplemented!("requested json output for a single field?"),
            _ => (),
        }

        let output = match field_query {
            Field::Username => match &entry.data {
                DecryptedData::Login { username, .. } => username.as_ref(),
                _ => None,
            },
            Field::Password => match &entry.data {
                DecryptedData::Login { password, .. } => password.as_ref(),
                _ => None,
            },
            Field::Notes =>
                entry.notes.as_ref(),
            Field::Custom(name) =>
                entry.fields.iter().find(|f| f.name.as_ref() == Some(name)).and_then(|f| f.value.as_ref()),
        };

        let output = output
            .ok_or_else(|| anyhow::anyhow!("Field {:?} not found on entry {}", field_query, entry.name))?;

        print!("{}", output);

        if rustix::termios::isatty(io::stdout()) {
            // Avoid writing a trailing newline otherwise
            println!();
        }

        return Ok(())
    }

    match opt.format {
        OutputFormat::Debug =>
            println!("{:#?}", entry),
        OutputFormat::Json =>
            unimplemented!("json output"),
        OutputFormat::Pass => {
            match &entry.data {
                DecryptedData::SecureNote { } => {
                    if let Some(notes) = &entry.notes {
                        println!("{}", notes);
                        return Ok(())
                    }
                },
                DecryptedData::Login { username, password, totp, uris } => {
                    if let Some(password) = password {
                        println!("{}", password);
                    }
                    if let Some(username) = username {
                        println!("login: {}", username);
                    }
                    if let Some(uris) = uris {
                        for uri in uris {
                            println!("url: {}", uri.uri);
                        }
                    }
                    if let Some(totp) = totp {
                        println!("otpauth://totp/?secret={}", totp);
                    }
                },
                DecryptedData::Card { cardholder_name, number, brand, exp_year, exp_month, code } => {
                    if let Some(number) = number {
                        println!("{}", number);
                    }
                    if let Some(name) = cardholder_name {
                        println!("name: {}", name);
                    }
                    if let Some(exp) = exp_year {
                        println!("exp_year: {}", exp);
                    }
                    if let Some(exp) = exp_month {
                        println!("exp_month: {}", exp);
                    }
                    if let Some(code) = code {
                        println!("cvv: {}", code);
                    }
                    if let Some(brand) = brand {
                        println!("brand: {}", brand);
                    }
                },
                DecryptedData::Identity { title, first_name, middle_name, last_name, address1, address2, address3, city, state, postal_code, country, phone, email, ssn, license_number, passport_number, username } => {
                    // TODO?
                    //entry.display_long(&entry.name);
                    println!("TODO: identity");
                    println!("name: {}", entry.name);
                },
            }

            for field in &entry.fields {
                let name = if let Some(name) = &field.name {
                    name
                } else {
                    log::warn!("skipping field with empty name");
                    continue
                };

                let value = if let Some(value) = &field.value {
                    value
                } else {
                    log::warn!("skipping field {} with empty value", name);
                    continue
                };

                println!("{}: {}", name, value);
            }

            match &entry.data {
                DecryptedData::SecureNote { } => (),
                _ => {
                    if let Some(notes) = &entry.notes {
                        println!("notes: {}", notes);
                    }
                },
            }
        },
    }

    Ok(())
}

async fn get_server_email(opt: &Opt) -> anyhow::Result<(String, String)> {
    let config = tokio::sync::OnceCell::new();
    let get_config = || config.get_or_try_init(|| rbw::config::Config::load_async());

    let email = match opt.email.clone() {
        Some(email) => email,
        None => get_config().await?.email.clone()
            .ok_or_else(|| anyhow::anyhow!("failed to find email address in config"))?,
    };

    let server = match opt.server.clone() {
        Some(server) => server,
        None => get_config().await?.server_name(),
    };

    Ok((server, email))
}

async fn load_db(opt: &Opt) -> anyhow::Result<rbw::db::Db> {
    let (server, email) = get_server_email(opt).await?;
    rbw::db::Db::load(&server, &email)
        .map_err(From::from)
}

async fn unlock(opt: &Opt, db: &rbw::db::Db) -> anyhow::Result<rbw::cipher::State> {
    let Some(kdf) = db.kdf else {
        return Err(anyhow::anyhow!("failed to find kdf type in db"));
    };

    let Some(iterations) = db.iterations else {
        return Err(anyhow::anyhow!(
            "failed to find number of iterations in db"
        ));
    };

    let memory = db.memory;
    let parallelism = db.parallelism;

    let Some(protected_key) = &db.protected_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected key in db"
        ));
    };
    let Some(protected_private_key) = &db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };

    let (_server, email) = get_server_email(opt).await?;

    let password = opt.password.read_password().await?;
    let (priv_key, org_keys) = rbw::actions::unlock(
        &email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
        protected_key,
        protected_private_key,
        &db.protected_org_keys,
    )?;

    Ok(State {
        org_keys: Some(org_keys),
        priv_key: Some(priv_key),
    })
}

async fn main_result(opt: &Opt) -> anyhow::Result<()> {
    match &opt.command {
        Command::Config { setting, value } => {
            let mut config = rbw::config::Config::load_async().await
                .unwrap_or_else(|_| rbw::config::Config::new());
            match setting {
                Setting::Email =>
                    config.email = Some(value.clone()),
                Setting::BaseUrl =>
                    config.base_url = Some(value.clone()),
                Setting::IdentityUrl =>
                    config.identity_url = Some(value.clone()),
            }
            config.save()?;
        },
        Command::List { query } => {
            let db = load_db(opt).await?;
            let mut crypt: rbw::cipher::State = unlock(opt, &db).await?;
            let mut entries = entries(&mut crypt, &db).collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(|(_, e)| e.folder.clone());
            let mut last_folder = None;
            for (cipher, entry) in entries.iter() {
                if let Some(query) = query {
                    // TODO: folder
                    let folder = None;
                    if entry.search_match(query, folder) {
                        continue
                    }
                }
                if last_folder != entry.folder.as_ref() {
                    if let Some(folder) = &entry.folder {
                        println!("{}", folder);
                    }
                }
                last_folder = entry.folder.as_ref();
                let prefix = if last_folder.is_none() {
                    "   "
                } else {
                    "├──"
                };
                println!("{}{}", prefix, entry.name);
            }
        },
        Command::Get { query, field } => {
            let db = load_db(opt).await?;
            let crypt: rbw::cipher::State = unlock(opt, &db).await?;

            let (_, entry) = find_by_entry(crypt, &db, query)?
                .ok_or_else(|| anyhow::anyhow!("no entry found"))?;
            output_entry(&opt, &entry, field)?;
        },
        Command::Login => {
            let mut db = load_db(opt).await
                .unwrap_or_else(|_| rbw::db::Db::new());
            let (server, email) = get_server_email(opt).await?;
            let password = opt.password.read_password().await?;
            let (two_factor_token, two_factor_provider) = (None, None); // TODO: aaa
            let res = rbw::actions::login(&email, password, two_factor_token, two_factor_provider).await;
            let (access_token, refresh_token, kdf, iterations, memory, paralellism, protected_key) = match res {
                Err(rbw::error::Error::TwoFactorRequired { providers }) =>
                    unimplemented!("2fa required"),
                Err(e) => return Err(e.into()),
                Ok(res) => res,
            };
            db.access_token = Some(access_token);
            db.refresh_token = Some(refresh_token);
            db.kdf = Some(kdf);
            db.iterations = Some(iterations);
            db.memory = memory;
            db.parallelism = paralellism;
            db.protected_key = Some(protected_key);
            db.save_async(&server, &email).await?;
        },
        Command::Register => {
            let mut db = load_db(opt).await
                .unwrap_or_else(|_| rbw::db::Db::new());
            let (server, email) = get_server_email(opt).await?;

            let client_id = todo!();
            let client_secret = todo!();
            let apikey = rbw::locked::ApiKey::new(client_id, client_secret);
            rbw::actions::register(&email, apikey).await?;
        },
        Command::Sync => {
            let (server, email) = get_server_email(opt).await?;
            let mut db = load_db(opt).await?;
            let access_token = db.access_token.as_ref()
                .ok_or_else(|| anyhow::anyhow!("login required"))?;
            let refresh_token = db.refresh_token.as_ref()
                .ok_or_else(|| anyhow::anyhow!("login required"))?;
            let res = rbw::actions::sync(access_token, refresh_token).await;
            let (access_token, (protected_key, protected_private_key, protected_org_keys, entries)) = res?;
            if let Some(access_token) = access_token {
                db.access_token = Some(access_token);
            }
            db.protected_key = Some(protected_key);
            db.protected_private_key = Some(protected_private_key);
            db.protected_org_keys = protected_org_keys;
            db.entries = entries;
            db.save(&server, &email)?;
        },
    }

    Ok(())
}

fn main() {
    let opt = Opt::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format(|buf, record| {
        if let Some((terminal_size::Width(w), _)) =
            terminal_size::terminal_size()
        {
            let out = format!("{}: {}", record.level(), record.args());
            writeln!(buf, "{}", textwrap::fill(&out, usize::from(w) - 1))
        } else {
            writeln!(buf, "{}: {}", record.level(), record.args())
        }
    })
    .init();

    let res = tokio::runtime::Runtime::new().unwrap().block_on(main_result(&opt));
    let res = res.context(format!("bitw {}", opt.command.subcommand_name()));

    if let Err(e) = res {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
