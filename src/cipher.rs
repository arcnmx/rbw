use crate::{db, locked, cipherstring};
use anyhow::Context as _;

pub trait Cipher {
    fn decrypt(
        &mut self,
        cipherstring: &str,
        org_id: Option<&str>,
    ) -> anyhow::Result<String>;

    fn encrypt(
        &mut self,
        plaintext: &str,
        org_id: Option<&str>,
    ) -> anyhow::Result<String>;
}

impl<'a, C: Cipher> Cipher for &'a mut C {
    fn decrypt(
        &mut self,
        cipherstring: &str,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        Cipher::decrypt(*self, cipherstring, org_id)
    }

    fn encrypt(
        &mut self,
        plaintext: &str,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        Cipher::encrypt(*self, plaintext, org_id)
    }
}

pub struct State {
    pub priv_key: locked::Keys,
    pub org_keys: std::collections::HashMap<String, locked::Keys>,
}

impl State {
    pub fn key(&self, org_id: Option<&str>) -> Option<&locked::Keys> {
        match org_id {
            Some(id) => self.org_keys.get(id),
            None => Some(&self.priv_key),
        }
    }
}

impl Cipher for State {
    fn decrypt(
        &mut self,
        cipherstring: &str,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        let keys = if let Some(keys) = self.key(org_id) {
            keys
        } else {
            return Err(anyhow::anyhow!(
                "failed to find decryption keys in state"
            ));
        };
        let cipherstring = cipherstring::CipherString::new(cipherstring)
            .context("failed to parse encrypted secret")?;
        let plaintext = String::from_utf8(
            cipherstring
                .decrypt_symmetric(&keys)
                .context("failed to decrypt encrypted secret")?,
        )
        .context("failed to parse decrypted secret")?;

        Ok(plaintext)
    }

    fn encrypt(
        &mut self,
        plaintext: &str,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        // TODO: return rbw::cipherstring::CipherString?
        let keys = if let Some(keys) = self.key(org_id) {
            keys
        } else {
            return Err(anyhow::anyhow!(
                "failed to find encryption keys in state"
            ));
        };
        let cipherstring = cipherstring::CipherString::encrypt_symmetric(
            keys,
            plaintext.as_bytes(),
        )
        .context("failed to encrypt plaintext secret")?;

        Ok(cipherstring.to_string())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DecryptedCipher {
    pub id: String,
    pub folder: Option<String>,
    pub name: String,
    pub data: DecryptedData,
    pub fields: Vec<DecryptedField>,
    pub notes: Option<String>,
    pub history: Vec<DecryptedHistoryEntry>,
}

impl DecryptedCipher {
    pub fn display_short(&self, desc: &str) -> bool {
        match &self.data {
            DecryptedData::Login { password, .. } => {
                if let Some(password) = password {
                    println!("{}", password);
                    true
                } else {
                    eprintln!("entry for '{}' had no password", desc);
                    false
                }
            }
            DecryptedData::Card { number, .. } => {
                if let Some(number) = number {
                    println!("{}", number);
                    true
                } else {
                    eprintln!("entry for '{}' had no card number", desc);
                    false
                }
            }
            DecryptedData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                let names: Vec<_> =
                    [title, first_name, middle_name, last_name]
                        .iter()
                        .copied()
                        .cloned()
                        .filter_map(|x| x)
                        .collect();
                if names.is_empty() {
                    eprintln!("entry for '{}' had no name", desc);
                    false
                } else {
                    println!("{}", names.join(" "));
                    true
                }
            }
            DecryptedData::SecureNote {} => {
                if let Some(notes) = &self.notes {
                    println!("{}", notes);
                    true
                } else {
                    eprintln!("entry for '{}' had no notes", desc);
                    false
                }
            }
        }
    }

    pub fn display_long(&self, desc: &str) {
        match &self.data {
            DecryptedData::Login {
                username,
                totp,
                uris,
                ..
            } => {
                let mut displayed = self.display_short(desc);
                displayed |=
                    self.display_field("Username", username.as_deref());
                displayed |=
                    self.display_field("TOTP Secret", totp.as_deref());

                if let Some(uris) = uris {
                    for uri in uris {
                        displayed |= self.display_field("URI", Some(uri));
                    }
                }

                for field in &self.fields {
                    displayed |= self.display_field(
                        field.name.as_deref().unwrap_or_else(|| "(null)"),
                        Some(field.value.as_deref().unwrap_or_else(|| "")),
                    );
                }

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{}", notes);
                }
            }
            DecryptedData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                let mut displayed = self.display_short(desc);

                if let (Some(exp_month), Some(exp_year)) =
                    (exp_month, exp_year)
                {
                    println!("Expiration: {}/{}", exp_month, exp_year);
                    displayed = true;
                }
                displayed |= self.display_field("CVV", code.as_deref());
                displayed |=
                    self.display_field("Name", cardholder_name.as_deref());
                displayed |= self.display_field("Brand", brand.as_deref());

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{}", notes);
                }
            }
            DecryptedData::Identity {
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
                ..
            } => {
                let mut displayed = self.display_short(desc);

                displayed |=
                    self.display_field("Address", address1.as_deref());
                displayed |=
                    self.display_field("Address", address2.as_deref());
                displayed |=
                    self.display_field("Address", address3.as_deref());
                displayed |= self.display_field("City", city.as_deref());
                displayed |= self.display_field("State", state.as_deref());
                displayed |=
                    self.display_field("Postcode", postal_code.as_deref());
                displayed |=
                    self.display_field("Country", country.as_deref());
                displayed |= self.display_field("Phone", phone.as_deref());
                displayed |= self.display_field("Email", email.as_deref());
                displayed |= self.display_field("SSN", ssn.as_deref());
                displayed |=
                    self.display_field("License", license_number.as_deref());
                displayed |= self
                    .display_field("Passport", passport_number.as_deref());
                displayed |=
                    self.display_field("Username", username.as_deref());

                if let Some(notes) = &self.notes {
                    if displayed {
                        println!();
                    }
                    println!("{}", notes);
                }
            }
            DecryptedData::SecureNote {} => {
                self.display_short(desc);
            }
        }
    }

    pub fn display_field(&self, name: &str, field: Option<&str>) -> bool {
        if let Some(field) = field {
            println!("{}: {}", name, field);
            true
        } else {
            false
        }
    }

    pub fn display_name(&self) -> String {
        match &self.data {
            DecryptedData::Login { username, .. } => {
                if let Some(username) = username {
                    format!("{}@{}", username, self.name)
                } else {
                    self.name.clone()
                }
            }
            _ => self.name.clone(),
        }
    }

    pub fn exact_match(
        &self,
        name: &str,
        username: Option<&str>,
        folder: Option<&str>,
        try_match_folder: bool,
    ) -> bool {
        if name != self.name {
            return false;
        }

        if let Some(given_username) = username {
            match &self.data {
                DecryptedData::Login { username, .. } => {
                    if let Some(found_username) = username {
                        if given_username != found_username {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                _ => {
                    // not sure what else to do here, but open to suggestions
                    return false;
                }
            }
        }

        if try_match_folder {
            if let Some(given_folder) = folder {
                if let Some(folder) = &self.folder {
                    if given_folder != folder {
                        return false;
                    }
                } else {
                    return false;
                }
            } else if self.folder.is_some() {
                return false;
            }
        }

        true
    }

    pub fn partial_match(
        &self,
        name: &str,
        username: Option<&str>,
        folder: Option<&str>,
        try_match_folder: bool,
    ) -> bool {
        if !self.name.contains(name) {
            return false;
        }

        if let Some(given_username) = username {
            match &self.data {
                DecryptedData::Login { username, .. } => {
                    if let Some(found_username) = username {
                        if !found_username.contains(given_username) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                _ => {
                    // not sure what else to do here, but open to suggestions
                    return false;
                }
            }
        }

        if try_match_folder {
            if let Some(given_folder) = folder {
                if let Some(folder) = &self.folder {
                    if !folder.contains(given_folder) {
                        return false;
                    }
                } else {
                    return false;
                }
            } else if self.folder.is_some() {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DecryptedData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Option<Vec<String>>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DecryptedField {
    pub name: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DecryptedHistoryEntry {
    pub last_used_date: String,
    pub password: String,
}

pub enum ListField {
    Name,
    Id,
    User,
    Folder,
}

impl std::convert::TryFrom<&String> for ListField {
    type Error = anyhow::Error;

    fn try_from(s: &String) -> anyhow::Result<Self> {
        Ok(match s.as_str() {
            "name" => Self::Name,
            "id" => Self::Id,
            "user" => Self::User,
            "folder" => Self::Folder,
            _ => return Err(anyhow::anyhow!("unknown field {}", s)),
        })
    }
}

pub fn generate_totp(secret: &str) -> anyhow::Result<String> {
    Ok(totp_lite::totp_custom::<totp_lite::Sha1>(
        totp_lite::DEFAULT_STEP,
        6,
        &base32::decode(
            base32::Alphabet::RFC4648 { padding: false },
            secret
        )
        .ok_or_else(|| anyhow::anyhow!(
            "totp secret was not valid base32"
        ))?,
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_secs(),
    ))
}

pub fn find_entry<C: Cipher>(
    mut crypt: C,
    db: &db::Db,
    name: &str,
    username: Option<&str>,
    folder: Option<&str>,
) -> anyhow::Result<(db::Entry, DecryptedCipher)> {
    match uuid::Uuid::parse_str(name) {
        Ok(_) => {
            for cipher in &db.entries {
                if name == cipher.id {
                    return Ok((cipher.clone(), decrypt_cipher(&mut crypt, &cipher)?));
                }
            }
            Err(anyhow::anyhow!("no entry found"))
        }
        Err(_) => {
            let ciphers: Vec<(db::Entry, DecryptedCipher)> = db
                .entries
                .iter()
                .cloned()
                .map(|entry| {
                    decrypt_cipher(&mut crypt, &entry).map(|decrypted| (entry, decrypted))
                })
                .collect::<anyhow::Result<_>>()?;
            find_entry_raw(&ciphers, name, username, folder)
        }
    }
}

pub fn find_entry_raw(
    entries: &[(db::Entry, DecryptedCipher)],
    name: &str,
    username: Option<&str>,
    folder: Option<&str>,
) -> anyhow::Result<(db::Entry, DecryptedCipher)> {
    let mut matches: Vec<(db::Entry, DecryptedCipher)> = entries
        .iter()
        .cloned()
        .filter(|(_, decrypted_cipher)| {
            decrypted_cipher.exact_match(name, username, folder, true)
        })
        .collect();

    if matches.len() == 1 {
        return Ok(matches[0].clone());
    }

    if folder.is_none() {
        matches = entries
            .iter()
            .cloned()
            .filter(|(_, decrypted_cipher)| {
                decrypted_cipher.exact_match(name, username, folder, false)
            })
            .collect();

        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }
    }

    matches = entries
        .iter()
        .cloned()
        .filter(|(_, decrypted_cipher)| {
            decrypted_cipher.partial_match(name, username, folder, true)
        })
        .collect();

    if matches.len() == 1 {
        return Ok(matches[0].clone());
    }

    if folder.is_none() {
        matches = entries
            .iter()
            .cloned()
            .filter(|(_, decrypted_cipher)| {
                decrypted_cipher.partial_match(name, username, folder, false)
            })
            .collect();
        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }
    }

    if matches.is_empty() {
        Err(anyhow::anyhow!("no entry found"))
    } else {
        let entries: Vec<String> = matches
            .iter()
            .map(|(_, decrypted)| decrypted.display_name())
            .collect();
        let entries = entries.join(", ");
        Err(anyhow::anyhow!("multiple entries found: {}", entries))
    }
}

pub fn decrypt_field<C: Cipher>(
    mut crypt: C,
    name: &str,
    field: Option<&str>,
    org_id: Option<&str>,
) -> Option<String> {
    let field = field
        .as_ref()
        .map(|field| crypt.decrypt(field, org_id))
        .transpose();
    match field {
        Ok(field) => field,
        Err(e) => {
            log::warn!("failed to decrypt {}: {}", name, e);
            None
        }
    }
}

pub fn decrypt_cipher<C: Cipher>(mut crypt: C, entry: &db::Entry) -> anyhow::Result<DecryptedCipher> {
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| crypt.decrypt(folder, None))
        .transpose();
    let folder = match folder {
        Ok(folder) => folder,
        Err(e) => {
            log::warn!("failed to decrypt folder name: {}", e);
            None
        }
    };
    let fields = entry
        .fields
        .iter()
        .map(|field| {
            Ok(DecryptedField {
                name: field
                    .name
                    .as_ref()
                    .map(|name| {
                        crypt.decrypt(
                            &name,
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                value: field
                    .value
                    .as_ref()
                    .map(|value| {
                        crypt.decrypt(
                            &value,
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| crypt.decrypt(notes, entry.org_id.as_deref()))
        .transpose();
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {}", e);
            None
        }
    };
    let history = entry
        .history
        .iter()
        .map(|history_entry| {
            Ok(DecryptedHistoryEntry {
                last_used_date: history_entry.last_used_date.clone(),
                password: crypt.decrypt(
                    &history_entry.password,
                    entry.org_id.as_deref(),
                )?,
            })
        })
        .collect::<anyhow::Result<_>>()?;

    let data = match &entry.data {
        db::EntryData::Login {
            username,
            password,
            totp,
            uris,
        } => DecryptedData::Login {
            username: decrypt_field(
                &mut crypt,
                "username",
                username.as_deref(),
                entry.org_id.as_deref(),
            ),
            password: decrypt_field(
                &mut crypt,
                "password",
                password.as_deref(),
                entry.org_id.as_deref(),
            ),
            totp: decrypt_field(
                &mut crypt,
                "totp",
                totp.as_deref(),
                entry.org_id.as_deref(),
            ),
            uris: uris
                .iter()
                .map(|s| {
                    decrypt_field(&mut crypt, "uri", Some(s), entry.org_id.as_deref())
                })
                .collect(),
        },
        db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: decrypt_field(
                &mut crypt,
                "cardholder_name",
                cardholder_name.as_deref(),
                entry.org_id.as_deref(),
            ),
            number: decrypt_field(
                &mut crypt,
                "number",
                number.as_deref(),
                entry.org_id.as_deref(),
            ),
            brand: decrypt_field(
                &mut crypt,
                "brand",
                brand.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_month: decrypt_field(
                &mut crypt,
                "exp_month",
                exp_month.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_year: decrypt_field(
                &mut crypt,
                "exp_year",
                exp_year.as_deref(),
                entry.org_id.as_deref(),
            ),
            code: decrypt_field(
                &mut crypt,
                "code",
                code.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        db::EntryData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => DecryptedData::Identity {
            title: decrypt_field(
                &mut crypt,
                "title",
                title.as_deref(),
                entry.org_id.as_deref(),
            ),
            first_name: decrypt_field(
                &mut crypt,
                "first_name",
                first_name.as_deref(),
                entry.org_id.as_deref(),
            ),
            middle_name: decrypt_field(
                &mut crypt,
                "middle_name",
                middle_name.as_deref(),
                entry.org_id.as_deref(),
            ),
            last_name: decrypt_field(
                &mut crypt,
                "last_name",
                last_name.as_deref(),
                entry.org_id.as_deref(),
            ),
            address1: decrypt_field(
                &mut crypt,
                "address1",
                address1.as_deref(),
                entry.org_id.as_deref(),
            ),
            address2: decrypt_field(
                &mut crypt,
                "address2",
                address2.as_deref(),
                entry.org_id.as_deref(),
            ),
            address3: decrypt_field(
                &mut crypt,
                "address3",
                address3.as_deref(),
                entry.org_id.as_deref(),
            ),
            city: decrypt_field(
                &mut crypt,
                "city",
                city.as_deref(),
                entry.org_id.as_deref(),
            ),
            state: decrypt_field(
                &mut crypt,
                "state",
                state.as_deref(),
                entry.org_id.as_deref(),
            ),
            postal_code: decrypt_field(
                &mut crypt,
                "postal_code",
                postal_code.as_deref(),
                entry.org_id.as_deref(),
            ),
            country: decrypt_field(
                &mut crypt,
                "country",
                country.as_deref(),
                entry.org_id.as_deref(),
            ),
            phone: decrypt_field(
                &mut crypt,
                "phone",
                phone.as_deref(),
                entry.org_id.as_deref(),
            ),
            email: decrypt_field(
                &mut crypt,
                "email",
                email.as_deref(),
                entry.org_id.as_deref(),
            ),
            ssn: decrypt_field(
                &mut crypt,
                "ssn",
                ssn.as_deref(),
                entry.org_id.as_deref(),
            ),
            license_number: decrypt_field(
                &mut crypt,
                "license_number",
                license_number.as_deref(),
                entry.org_id.as_deref(),
            ),
            passport_number: decrypt_field(
                &mut crypt,
                "passport_number",
                passport_number.as_deref(),
                entry.org_id.as_deref(),
            ),
            username: decrypt_field(
                &mut crypt,
                "username",
                username.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        db::EntryData::SecureNote {} => DecryptedData::SecureNote {},
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder,
        name: crypt.decrypt(&entry.name, entry.org_id.as_deref())?,
        data,
        fields,
        notes,
        history,
    })
}
