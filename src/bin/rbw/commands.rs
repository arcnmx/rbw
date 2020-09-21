use anyhow::Context as _;
use rbw::cipher::*;

const MISSING_CONFIG_HELP: &str =
    "Before using rbw, you must configure the email address you would like to \
    use to log in to the server by running:\n\n    \
        rbw config set email <email>\n\n\
    Additionally, if you are using a self-hosted installation, you should \
    run:\n\n    \
        rbw config set base_url <url>\n\n\
    and, if your server has a non-default identity url:\n\n    \
        rbw config set identity_url <url>\n";

const HELP: &str = r#"
# The first line of this file will be the password, and the remainder of the
# file (after any blank lines after the password) will be stored as a note.
# Lines with leading # will be ignored.
"#;

pub fn config_show() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    serde_json::to_writer_pretty(std::io::stdout(), &config)
        .context("failed to write config to stdout")?;
    println!();

    Ok(())
}

pub fn config_set(key: &str, value: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = Some(value.to_string()),
        "base_url" => config.base_url = Some(value.to_string()),
        "identity_url" => config.identity_url = Some(value.to_string()),
        "lock_timeout" => {
            let timeout = value
                .parse()
                .context("failed to parse value for lock_timeout")?;
            if timeout == 0 {
                log::error!("lock_timeout must be greater than 0");
            } else {
                config.lock_timeout = timeout;
            }
        }
        _ => return Err(anyhow::anyhow!("invalid config key: {}", key)),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}

pub fn config_unset(key: &str) -> anyhow::Result<()> {
    let mut config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    match key {
        "email" => config.email = None,
        "base_url" => config.base_url = None,
        "identity_url" => config.identity_url = None,
        "lock_timeout" => {
            config.lock_timeout = rbw::config::default_lock_timeout()
        }
        _ => return Err(anyhow::anyhow!("invalid config key: {}", key)),
    }
    config.save()?;

    // drop in-memory keys, since they will be different if the email or url
    // changed. not using lock() because we don't want to require the agent to
    // be running (since this may be the user running `rbw config set
    // base_url` as the first operation), and stop_agent() already handles the
    // agent not running case gracefully.
    stop_agent()?;

    Ok(())
}

pub fn login() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;

    Ok(())
}

pub fn unlock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::unlock()?;

    Ok(())
}

pub fn unlocked() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::unlocked()?;

    Ok(())
}

pub fn sync() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::login()?;
    crate::actions::sync()?;

    Ok(())
}

pub fn list(fields: &[String]) -> anyhow::Result<()> {
    let fields: Vec<ListField> = fields
        .iter()
        .map(std::convert::TryFrom::try_from)
        .collect::<anyhow::Result<_>>()?;

    unlock()?;

    let mut sock = crate::actions::connect()?;

    let db = load_db()?;
    let mut ciphers: Vec<DecryptedCipher> = db
        .entries
        .iter()
        .cloned()
        .map(|entry| decrypt_cipher(&mut sock, &entry))
        .collect::<anyhow::Result<_>>()?;
    ciphers.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    for cipher in ciphers {
        let values: Vec<String> = fields
            .iter()
            .map(|field| match field {
                ListField::Name => cipher.name.clone(),
                ListField::Id => cipher.id.clone(),
                ListField::User => match &cipher.data {
                    DecryptedData::Login { username, .. } => username
                        .as_ref()
                        .map(std::string::ToString::to_string)
                        .unwrap_or_else(|| "".to_string()),
                    _ => "".to_string(),
                },
                ListField::Folder => cipher
                    .folder
                    .as_ref()
                    .map(std::string::ToString::to_string)
                    .unwrap_or_else(|| "".to_string()),
            })
            .collect();
        println!("{}", values.join("\t"));
    }

    Ok(())
}

pub fn get(
    name: &str,
    user: Option<&str>,
    folder: Option<&str>,
    full: bool,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        user.map(|s| format!("{}@", s))
            .unwrap_or_else(|| "".to_string()),
        name
    );

    let sock = crate::actions::connect()?;

    let (_, decrypted) = find_entry(sock, &db, name, user, folder)
        .with_context(|| format!("couldn't find entry for '{}'", desc))?;
    if full {
        decrypted.display_long(&desc);
    } else {
        decrypted.display_short(&desc);
    }

    Ok(())
}

pub fn code(
    name: &str,
    user: Option<&str>,
    folder: Option<&str>,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        user.map(|s| format!("{}@", s))
            .unwrap_or_else(|| "".to_string()),
        name
    );

    let sock = crate::actions::connect()?;

    let (_, decrypted) = find_entry(sock, &db, name, user, folder)
        .with_context(|| format!("couldn't find entry for '{}'", desc))?;

    if let DecryptedData::Login { totp, .. } = decrypted.data {
        if let Some(totp) = totp {
            println!("{}", generate_totp(&totp)?)
        } else {
            return Err(anyhow::anyhow!(
                "entry does not contain a totp secret"
            ));
        }
    } else {
        return Err(anyhow::anyhow!("not a login entry"));
    }

    Ok(())
}

pub fn add(
    name: &str,
    username: Option<&str>,
    uris: Vec<String>,
    folder: Option<&str>,
) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;
    // unwrap is safe here because the call to unlock above is guaranteed to
    // populate these or error
    let mut access_token = db.access_token.as_ref().unwrap().clone();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let name = crate::actions::encrypt(name, None)?;

    let username = username
        .map(|username| crate::actions::encrypt(username, None))
        .transpose()?;

    let contents = rbw::edit::edit("", HELP)?;

    let (password, notes) = parse_editor(&contents);
    let password = password
        .map(|password| crate::actions::encrypt(&password, None))
        .transpose()?;
    let notes = notes
        .map(|notes| crate::actions::encrypt(&notes, None))
        .transpose()?;
    let uris: Vec<String> = uris
        .iter()
        .map(|uri| crate::actions::encrypt(&uri, None))
        .collect::<anyhow::Result<_>>()?;

    let mut folder_id = None;
    if let Some(folder_name) = folder {
        let (new_access_token, folders) =
            rbw::actions::list_folders(&access_token, &refresh_token)?;
        if let Some(new_access_token) = new_access_token {
            access_token = new_access_token.clone();
            db.access_token = Some(new_access_token);
            save_db(&db)?;
        }

        let folders: Vec<(String, String)> = folders
            .iter()
            .cloned()
            .map(|(id, name)| Ok((id, crate::actions::decrypt(&name, None)?)))
            .collect::<anyhow::Result<_>>()?;

        for (id, name) in folders {
            if name == folder_name {
                folder_id = Some(id);
            }
        }
        if folder_id.is_none() {
            let (new_access_token, id) = rbw::actions::create_folder(
                &access_token,
                &refresh_token,
                &crate::actions::encrypt(folder_name, None)?,
            )?;
            if let Some(new_access_token) = new_access_token {
                access_token = new_access_token.clone();
                db.access_token = Some(new_access_token);
                save_db(&db)?;
            }
            folder_id = Some(id);
        }
    }

    if let (Some(access_token), ()) = rbw::actions::add(
        &access_token,
        &refresh_token,
        &name,
        &rbw::db::EntryData::Login {
            username,
            password,
            uris,
            totp: None,
        },
        notes.as_deref(),
        folder_id.as_deref(),
    )? {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub fn generate(
    name: Option<&str>,
    username: Option<&str>,
    uris: Vec<String>,
    folder: Option<&str>,
    len: usize,
    ty: rbw::pwgen::Type,
) -> anyhow::Result<()> {
    let password = rbw::pwgen::pwgen(ty, len);
    println!("{}", password);

    if let Some(name) = name {
        unlock()?;

        let mut db = load_db()?;
        // unwrap is safe here because the call to unlock above is guaranteed
        // to populate these or error
        let mut access_token = db.access_token.as_ref().unwrap().clone();
        let refresh_token = db.refresh_token.as_ref().unwrap();

        let name = crate::actions::encrypt(name, None)?;
        let username = username
            .map(|username| crate::actions::encrypt(username, None))
            .transpose()?;
        let password = crate::actions::encrypt(&password, None)?;
        let uris: Vec<String> = uris
            .iter()
            .map(|uri| crate::actions::encrypt(&uri, None))
            .collect::<anyhow::Result<_>>()?;

        let mut folder_id = None;
        if let Some(folder_name) = folder {
            let (new_access_token, folders) =
                rbw::actions::list_folders(&access_token, &refresh_token)?;
            if let Some(new_access_token) = new_access_token {
                access_token = new_access_token.clone();
                db.access_token = Some(new_access_token);
                save_db(&db)?;
            }

            let folders: Vec<(String, String)> = folders
                .iter()
                .cloned()
                .map(|(id, name)| {
                    Ok((id, crate::actions::decrypt(&name, None)?))
                })
                .collect::<anyhow::Result<_>>()?;

            for (id, name) in folders {
                if name == folder_name {
                    folder_id = Some(id);
                }
            }
            if folder_id.is_none() {
                let (new_access_token, id) = rbw::actions::create_folder(
                    &access_token,
                    &refresh_token,
                    &crate::actions::encrypt(folder_name, None)?,
                )?;
                if let Some(new_access_token) = new_access_token {
                    access_token = new_access_token.clone();
                    db.access_token = Some(new_access_token);
                    save_db(&db)?;
                }
                folder_id = Some(id);
            }
        }

        if let (Some(access_token), ()) = rbw::actions::add(
            &access_token,
            &refresh_token,
            &name,
            &rbw::db::EntryData::Login {
                username,
                password: Some(password),
                uris,
                totp: None,
            },
            None,
            folder_id.as_deref(),
        )? {
            db.access_token = Some(access_token);
            save_db(&db)?;
        }

        crate::actions::sync()?;
    }

    Ok(())
}

pub fn edit(
    name: &str,
    username: Option<&str>,
    folder: Option<&str>,
) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let desc = format!(
        "{}{}",
        username
            .map(|s| format!("{}@", s))
            .unwrap_or_else(|| "".to_string()),
        name
    );

    let sock = crate::actions::connect()?;

    let (entry, decrypted) = find_entry(sock, &db, name, username, folder)
        .with_context(|| format!("couldn't find entry for '{}'", desc))?;

    let (data, notes, history) = match &decrypted.data {
        DecryptedData::Login { password, .. } => {
            let mut contents =
                format!("{}\n", password.as_deref().unwrap_or(""));
            if let Some(notes) = decrypted.notes {
                contents.push_str(&format!("\n{}\n", notes));
            }

            let contents = rbw::edit::edit(&contents, HELP)?;

            let (password, notes) = parse_editor(&contents);
            let password = password
                .map(|password| {
                    crate::actions::encrypt(
                        &password,
                        entry.org_id.as_deref(),
                    )
                })
                .transpose()?;
            let notes = notes
                .map(|notes| {
                    crate::actions::encrypt(&notes, entry.org_id.as_deref())
                })
                .transpose()?;
            let mut history = entry.history.clone();
            let (entry_username, entry_password, entry_uris, entry_totp) =
                match &entry.data {
                    rbw::db::EntryData::Login {
                        username,
                        password,
                        uris,
                        totp,
                    } => (username, password, uris, totp),
                    _ => unreachable!(),
                };
            let new_history_entry = rbw::db::HistoryEntry {
                last_used_date: format!(
                    "{}",
                    humantime::format_rfc3339(std::time::SystemTime::now())
                ),
                password: entry_password.clone().unwrap_or_else(String::new),
            };
            history.insert(0, new_history_entry);
            let data = rbw::db::EntryData::Login {
                username: entry_username.clone(),
                password,
                uris: entry_uris.to_vec(),
                totp: entry_totp.clone(),
            };
            (data, notes, history)
        }
        _ => {
            return Err(anyhow::anyhow!(
                "modifications are only supported for login entries"
            ));
        }
    };

    if let (Some(access_token), ()) = rbw::actions::edit(
        &access_token,
        &refresh_token,
        &entry.id,
        entry.org_id.as_deref(),
        &entry.name,
        &data,
        notes.as_deref(),
        entry.folder_id.as_deref(),
        &history,
    )? {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;
    Ok(())
}

pub fn remove(
    name: &str,
    username: Option<&str>,
    folder: Option<&str>,
) -> anyhow::Result<()> {
    unlock()?;

    let mut db = load_db()?;
    let access_token = db.access_token.as_ref().unwrap();
    let refresh_token = db.refresh_token.as_ref().unwrap();

    let desc = format!(
        "{}{}",
        username
            .map(|s| format!("{}@", s))
            .unwrap_or_else(|| "".to_string()),
        name
    );

    let sock = crate::actions::connect()?;

    let (entry, _) = find_entry(sock, &db, name, username, folder)
        .with_context(|| format!("couldn't find entry for '{}'", desc))?;

    if let (Some(access_token), ()) =
        rbw::actions::remove(&access_token, &refresh_token, &entry.id)?
    {
        db.access_token = Some(access_token);
        save_db(&db)?;
    }

    crate::actions::sync()?;

    Ok(())
}

pub fn history(
    name: &str,
    username: Option<&str>,
    folder: Option<&str>,
) -> anyhow::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        username
            .map(|s| format!("{}@", s))
            .unwrap_or_else(|| "".to_string()),
        name
    );

    let sock = crate::actions::connect()?;

    let (_, decrypted) = find_entry(sock, &db, name, username, folder)
        .with_context(|| format!("couldn't find entry for '{}'", desc))?;
    for history in decrypted.history {
        println!("{}: {}", history.last_used_date, history.password);
    }

    Ok(())
}

pub fn lock() -> anyhow::Result<()> {
    ensure_agent()?;
    crate::actions::lock()?;

    Ok(())
}

pub fn purge() -> anyhow::Result<()> {
    stop_agent()?;

    remove_db()?;

    Ok(())
}

pub fn stop_agent() -> anyhow::Result<()> {
    crate::actions::quit()?;

    Ok(())
}

fn ensure_agent() -> anyhow::Result<()> {
    check_config()?;

    ensure_agent_once()?;
    let client_version = rbw::protocol::version();
    let agent_version = version_or_quit()?;
    if agent_version != client_version {
        log::debug!(
            "client protocol version is {} but agent protocol version is {}",
            client_version,
            agent_version
        );
        crate::actions::quit()?;
        ensure_agent_once()?;
        let agent_version = version_or_quit()?;
        if agent_version != client_version {
            crate::actions::quit()?;
            return Err(anyhow::anyhow!(
                "incompatible protocol versions: client ({}), agent ({})",
                client_version,
                agent_version
            ));
        }
    }
    Ok(())
}

fn ensure_agent_once() -> anyhow::Result<()> {
    let agent_path = std::env::var("RBW_AGENT");
    let agent_path = agent_path
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("rbw-agent");
    let status = std::process::Command::new(agent_path)
        .status()
        .context("failed to run rbw-agent")?;
    if !status.success() {
        if let Some(code) = status.code() {
            if code != 23 {
                return Err(anyhow::anyhow!(
                    "failed to run rbw-agent: {}",
                    status
                ));
            }
        }
    }

    Ok(())
}

fn check_config() -> anyhow::Result<()> {
    rbw::config::Config::validate().map_err(|e| {
        log::error!("{}", MISSING_CONFIG_HELP);
        anyhow::Error::new(e)
    })
}

fn version_or_quit() -> anyhow::Result<u32> {
    crate::actions::version().or_else(|e| {
        let _ = crate::actions::quit();
        Err(e)
    })
}

fn parse_editor(contents: &str) -> (Option<String>, Option<String>) {
    let mut lines = contents.lines();

    let password = lines.next().map(std::string::ToString::to_string);

    let mut notes: String = lines
        .skip_while(|line| *line == "")
        .filter(|line| !line.starts_with('#'))
        .map(|line| format!("{}\n", line))
        .collect();
    while notes.ends_with('\n') {
        notes.pop();
    }
    let notes = if notes == "" { None } else { Some(notes) };

    (password, notes)
}

fn load_db() -> anyhow::Result<rbw::db::Db> {
    let config = rbw::config::Config::load()?;
    if let Some(email) = &config.email {
        rbw::db::Db::load(&config.server_name(), &email)
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

fn save_db(db: &rbw::db::Db) -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    if let Some(email) = &config.email {
        db.save(&config.server_name(), &email)
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

fn remove_db() -> anyhow::Result<()> {
    let config = rbw::config::Config::load()?;
    if let Some(email) = &config.email {
        rbw::db::Db::remove(&config.server_name(), &email)
            .map_err(anyhow::Error::new)
    } else {
        Err(anyhow::anyhow!("failed to find email address in config"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_find_entry() {
        let entries = &[
            make_entry("github", Some("foo"), None),
            make_entry("gitlab", Some("foo"), None),
            make_entry("gitlab", Some("bar"), None),
            make_entry("gitter", Some("baz"), None),
            make_entry("git", Some("foo"), None),
            make_entry("bitwarden", None, None),
            make_entry("github", Some("foo"), Some("websites")),
            make_entry("github", Some("foo"), Some("ssh")),
            make_entry("github", Some("root"), Some("ssh")),
        ];

        assert!(
            one_match(entries, "github", Some("foo"), None, 0),
            "foo@github"
        );
        assert!(one_match(entries, "github", None, None, 0), "github");
        assert!(
            one_match(entries, "gitlab", Some("foo"), None, 1),
            "foo@gitlab"
        );
        assert!(one_match(entries, "git", Some("bar"), None, 2), "bar@git");
        assert!(
            one_match(entries, "gitter", Some("ba"), None, 3),
            "ba@gitter"
        );
        assert!(one_match(entries, "git", Some("foo"), None, 4), "foo@git");
        assert!(one_match(entries, "git", None, None, 4), "git");
        assert!(one_match(entries, "bitwarden", None, None, 5), "bitwarden");
        assert!(
            one_match(entries, "github", Some("foo"), Some("websites"), 6),
            "websites/foo@github"
        );
        assert!(
            one_match(entries, "github", Some("foo"), Some("ssh"), 7),
            "ssh/foo@github"
        );
        assert!(
            one_match(entries, "github", Some("root"), None, 8),
            "ssh/root@github"
        );

        assert!(
            no_matches(entries, "gitlab", Some("baz"), None),
            "baz@gitlab"
        );
        assert!(
            no_matches(entries, "bitbucket", Some("foo"), None),
            "foo@bitbucket"
        );
        assert!(
            no_matches(entries, "github", Some("foo"), Some("bar")),
            "bar/foo@github"
        );
        assert!(
            no_matches(entries, "gitlab", Some("foo"), Some("bar")),
            "bar/foo@gitlab"
        );

        assert!(many_matches(entries, "gitlab", None, None), "gitlab");
        assert!(many_matches(entries, "gi", Some("foo"), None), "foo@gi");
        assert!(many_matches(entries, "git", Some("ba"), None), "ba@git");
        assert!(
            many_matches(entries, "github", Some("foo"), Some("s")),
            "s/foo@github"
        );
    }

    fn one_match(
        entries: &[(rbw::db::Entry, DecryptedCipher)],
        name: &str,
        username: Option<&str>,
        folder: Option<&str>,
        idx: usize,
    ) -> bool {
        entries_eq(
            &find_entry_raw(entries, name, username, folder).unwrap(),
            &entries[idx],
        )
    }

    fn no_matches(
        entries: &[(rbw::db::Entry, DecryptedCipher)],
        name: &str,
        username: Option<&str>,
        folder: Option<&str>,
    ) -> bool {
        let res = find_entry_raw(entries, name, username, folder);
        if let Err(e) = res {
            format!("{}", e).contains("no entry found")
        } else {
            false
        }
    }

    fn many_matches(
        entries: &[(rbw::db::Entry, DecryptedCipher)],
        name: &str,
        username: Option<&str>,
        folder: Option<&str>,
    ) -> bool {
        let res = find_entry_raw(entries, name, username, folder);
        if let Err(e) = res {
            format!("{}", e).contains("multiple entries found")
        } else {
            false
        }
    }

    fn entries_eq(
        a: &(rbw::db::Entry, DecryptedCipher),
        b: &(rbw::db::Entry, DecryptedCipher),
    ) -> bool {
        a.0 == b.0 && a.1 == b.1
    }

    fn make_entry(
        name: &str,
        username: Option<&str>,
        folder: Option<&str>,
    ) -> (rbw::db::Entry, DecryptedCipher) {
        (
            rbw::db::Entry {
                id: "irrelevant".to_string(),
                org_id: None,
                folder: folder.map(|_| "encrypted folder name".to_string()),
                folder_id: None,
                name: "this is the encrypted name".to_string(),
                data: rbw::db::EntryData::Login {
                    username: username.map(|_| {
                        "this is the encrypted username".to_string()
                    }),
                    password: None,
                    uris: vec![],
                    totp: None,
                },
                fields: vec![],
                notes: None,
                history: vec![],
            },
            DecryptedCipher {
                id: "irrelevant".to_string(),
                folder: folder.map(std::string::ToString::to_string),
                name: name.to_string(),
                data: DecryptedData::Login {
                    username: username.map(std::string::ToString::to_string),
                    password: None,
                    totp: None,
                    uris: None,
                },
                fields: vec![],
                notes: None,
                history: vec![],
            },
        )
    }
}
