use crate::api::{FieldType, UriMatchType};
use crate::{db, locked};
use crate::cipherstring::CipherString;
use anyhow::Context as _;
use serde::Serialize;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::path::Path;
use std::str::FromStr;
use url::Url;

pub trait Cipher {
    fn decrypt(
        &mut self,
        cipherstring: &str,
        entry_key: Option<&str>,
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
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        Cipher::decrypt(*self, cipherstring, entry_key, org_id)
    }

    fn encrypt(
        &mut self,
        plaintext: &str,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        Cipher::encrypt(*self, plaintext, org_id)
    }
}

#[derive(Debug, Clone)]
pub enum Needle {
    Name(String),
    Uri(Url),
    Uuid(uuid::Uuid),
}

impl Needle {
    pub fn new(arg: &str) -> Self {
        if let Ok(uuid) = uuid::Uuid::parse_str(arg) {
            return Needle::Uuid(uuid);
        }
        if let Ok(url) = Url::parse(arg) {
            if url.is_special() {
                return Needle::Uri(url);
            }
        }

        Needle::Name(arg.to_string())
    }

    pub fn split_folder(&self) -> anyhow::Result<(Option<String>, Self)> {
        let name = match self {
            Needle::Name(name) => name,
            needle => return Ok((None, needle.clone())),
        };
        let path = Path::new(name);
        let name = path.file_name()
            .ok_or_else(|| anyhow::anyhow!("no name provided"))?;
        let folder = match path.parent().unwrap() {
            p if p == Path::new("") => None,
            p if p == Path::new("/") => Some(Path::new("")),
            p => Some(p),
        };

        let folder = folder.map(|f| f.to_str().unwrap().to_owned());
        let name = name.to_str().unwrap().to_owned();

        Ok((folder, Needle::Name(name)))
    }
}

impl Display for Needle {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let value = match &self {
            Self::Name(name) => name.clone(),
            Self::Uri(uri) => uri.to_string(),
            Self::Uuid(uuid) => uuid.to_string(),
        };
        write!(f, "{value}")
    }
}

impl FromStr for Needle {
    type Err = std::convert::Infallible;

    #[allow(clippy::unnecessary_wraps)]
    fn from_str(arg: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(arg))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
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
    pub fn exact_match(
        &self,
        needle: &Needle,
        username: Option<&str>,
        folder: Option<&str>,
        try_match_folder: bool,
        ignore_case: bool,
    ) -> bool {
        match needle {
            Needle::Name(name) => {
                if !((ignore_case
                    && name.to_lowercase() == self.name.to_lowercase())
                    || *name == self.name)
                {
                    return false;
                }
            }
            Needle::Uri(given_uri) => {
                match &self.data {
                    DecryptedData::Login {
                        uris: Some(uris), ..
                    } => {
                        if !uris.iter().any(|uri| uri.matches_url(given_uri))
                        {
                            return false;
                        }
                    }
                    _ => {
                        // not sure what else to do here, but open to suggestions
                        return false;
                    }
                }
            }
            Needle::Uuid(uuid) => {
                if uuid::Uuid::parse_str(&self.id) != Ok(*uuid) {
                    return false;
                }
            }
        }

        if let Some(given_username) = username {
            match &self.data {
                DecryptedData::Login {
                    username: Some(found_username),
                    ..
                } => {
                    if given_username != found_username {
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
        ignore_case: bool,
    ) -> bool {
        if !((ignore_case
            && self.name.to_lowercase().contains(&name.to_lowercase()))
            || self.name.contains(name))
        {
            return false;
        }

        if let Some(given_username) = username {
            match &self.data {
                DecryptedData::Login {
                    username: Some(found_username),
                    ..
                } => {
                    if !((ignore_case
                        && found_username
                            .to_lowercase()
                            .contains(&given_username.to_lowercase()))
                        || found_username.contains(given_username))
                    {
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

    pub fn search_match(&self, term: &str, folder: Option<&str>) -> bool {
        if let Some(folder) = folder {
            if self.folder.as_deref() != Some(folder) {
                return false;
            }
        }

        let fields = [
            Some(self.name.as_str()),
            self.notes.as_deref(),
            if let DecryptedData::Login {
                username: Some(username),
                ..
            } = &self.data
            {
                Some(username)
            } else {
                None
            },
        ];
        for field in fields
            .iter()
            .filter_map(|field| field.map(std::string::ToString::to_string))
            .chain(self.fields.iter().filter_map(|field| {
                field.value.as_ref().map(std::string::ToString::to_string)
            }))
        {
            if field.to_lowercase().contains(&term.to_lowercase()) {
                return true;
            }
        }

        false
    }

    pub fn display_name(&self) -> String {
        match &self.data {
            DecryptedData::Login { username, .. } => {
                username.as_ref().map_or_else(
                    || self.name.clone(),
                    |username| format!("{}@{}", username, self.name),
                )
            }
            _ => self.name.clone(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum DecryptedData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Option<Vec<DecryptedUri>>,
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DecryptedField {
    pub name: Option<String>,
    pub value: Option<String>,
    #[serde(serialize_with = "serialize_field_type", rename = "type")]
    pub ty: FieldType,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn serialize_field_type<S>(
    ty: &FieldType,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let s = match ty {
        FieldType::Text => "text",
        FieldType::Hidden => "hidden",
        FieldType::Boolean => "boolean",
        FieldType::Linked => "linked",
    };
    serializer.serialize_str(s)
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DecryptedHistoryEntry {
    pub last_used_date: String,
    pub password: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct DecryptedUri {
    pub uri: String,
    pub match_type: Option<UriMatchType>,
}

fn host_port(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    Some(
        url.port().map_or_else(
            || host.to_string(),
            |port| format!("{host}:{port}"),
        ),
    )
}

fn domain_port(url: &Url) -> Option<String> {
    let domain = url.domain()?;
    Some(url.port().map_or_else(
        || domain.to_string(),
        |port| format!("{domain}:{port}"),
    ))
}

impl DecryptedUri {
    fn matches_url(&self, url: &Url) -> bool {
        match self.match_type.unwrap_or(UriMatchType::Domain) {
            UriMatchType::Domain => {
                let Some(given_domain_port) = domain_port(url) else {
                    return false;
                };
                if let Ok(self_url) = url::Url::parse(&self.uri) {
                    if let Some(self_domain_port) = domain_port(&self_url) {
                        if self_url.scheme() == url.scheme()
                            && (self_domain_port == given_domain_port
                                || given_domain_port.ends_with(&format!(
                                    ".{self_domain_port}"
                                )))
                        {
                            return true;
                        }
                    }
                }
                self.uri == given_domain_port
                    || given_domain_port.ends_with(&format!(".{}", self.uri))
            }
            UriMatchType::Host => {
                let Some(given_host_port) = host_port(url) else {
                    return false;
                };
                if let Ok(self_url) = url::Url::parse(&self.uri) {
                    if let Some(self_host_port) = host_port(&self_url) {
                        if self_url.scheme() == url.scheme()
                            && self_host_port == given_host_port
                        {
                            return true;
                        }
                    }
                }
                self.uri == given_host_port
            }
            UriMatchType::StartsWith => {
                url.to_string().starts_with(&self.uri)
            }
            UriMatchType::Exact => url.to_string() == self.uri,
            UriMatchType::RegularExpression => {
                let Ok(rx) = regex::Regex::new(&self.uri) else {
                    return false;
                };
                rx.is_match(url.as_ref())
            }
            UriMatchType::Never => false,
        }
    }
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

pub fn find_entry<C: Cipher>(
    mut crypt: C,
    db: &db::Db,
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(db::Entry, DecryptedCipher)> {
    if let Needle::Uuid(uuid) = needle {
        for cipher in &db.entries {
            if uuid::Uuid::parse_str(&cipher.id) == Ok(*uuid) {
                return Ok((cipher.clone(), decrypt_cipher(&mut crypt, cipher)?));
            }
        }
        Err(anyhow::anyhow!("no entry found"))
    } else {
        let ciphers: Vec<(db::Entry, DecryptedCipher)> = db
            .entries
            .iter()
            .map(|entry| {
                decrypt_cipher(&mut crypt, entry)
                    .map(|decrypted| (entry.clone(), decrypted))
            })
            .collect::<anyhow::Result<_>>()?;
        find_entry_raw(&ciphers, needle, username, folder, ignore_case)
    }
}

pub fn find_entry_raw(
    entries: &[(db::Entry, DecryptedCipher)],
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> anyhow::Result<(db::Entry, DecryptedCipher)> {
    let mut matches: Vec<(db::Entry, DecryptedCipher)> = entries
        .iter()
        .filter(|&(_, decrypted_cipher)| {
            decrypted_cipher.exact_match(
                needle,
                username,
                folder,
                true,
                ignore_case,
            )
        })
        .cloned()
        .collect();

    if matches.len() == 1 {
        return Ok(matches[0].clone());
    }

    if folder.is_none() {
        matches = entries
            .iter()
            .filter(|&(_, decrypted_cipher)| {
                decrypted_cipher.exact_match(
                    needle,
                    username,
                    folder,
                    false,
                    ignore_case,
                )
            })
            .cloned()
            .collect();

        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }
    }

    if let Needle::Name(name) = needle {
        matches = entries
            .iter()
            .filter(|&(_, decrypted_cipher)| {
                decrypted_cipher.partial_match(
                    name,
                    username,
                    folder,
                    true,
                    ignore_case,
                )
            })
            .cloned()
            .collect();

        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }

        if folder.is_none() {
            matches = entries
                .iter()
                .filter(|&(_, decrypted_cipher)| {
                    decrypted_cipher.partial_match(
                        name,
                        username,
                        folder,
                        false,
                        ignore_case,
                    )
                })
                .cloned()
                .collect();
            if matches.len() == 1 {
                return Ok(matches[0].clone());
            }
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
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> Option<String> {
    let field = field
        .as_ref()
        .map(|field| crypt.decrypt(field, entry_key, org_id))
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
        .map(|folder| crypt.decrypt(folder, None, None))
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
                            name,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                value: field
                    .value
                    .as_ref()
                    .map(|value| {
                        crypt.decrypt(
                            value,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                ty: field.ty,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            crypt.decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
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
                    entry.key.as_deref(),
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
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            password: decrypt_field(
                &mut crypt,
                "password",
                password.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            totp: decrypt_field(
                &mut crypt,
                "totp",
                totp.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            uris: uris
                .iter()
                .map(|s| {
                    decrypt_field(
                        &mut crypt,
                        "uri",
                        Some(&s.uri),
                        entry.key.as_deref(),
                        entry.org_id.as_deref(),
                    )
                    .map(|uri| DecryptedUri {
                        uri,
                        match_type: s.match_type,
                    })
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
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            number: decrypt_field(
                &mut crypt,
                "number",
                number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            brand: decrypt_field(
                &mut crypt,
                "brand",
                brand.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_month: decrypt_field(
                &mut crypt,
                "exp_month",
                exp_month.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_year: decrypt_field(
                &mut crypt,
                "exp_year",
                exp_year.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            code: decrypt_field(
                &mut crypt,
                "code",
                code.as_deref(),
                entry.key.as_deref(),
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
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            first_name: decrypt_field(
                &mut crypt,
                "first_name",
                first_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            middle_name: decrypt_field(
                &mut crypt,
                "middle_name",
                middle_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            last_name: decrypt_field(
                &mut crypt,
                "last_name",
                last_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address1: decrypt_field(
                &mut crypt,
                "address1",
                address1.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address2: decrypt_field(
                &mut crypt,
                "address2",
                address2.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address3: decrypt_field(
                &mut crypt,
                "address3",
                address3.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            city: decrypt_field(
                &mut crypt,
                "city",
                city.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            state: decrypt_field(
                &mut crypt,
                "state",
                state.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            postal_code: decrypt_field(
                &mut crypt,
                "postal_code",
                postal_code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            country: decrypt_field(
                &mut crypt,
                "country",
                country.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            phone: decrypt_field(
                &mut crypt,
                "phone",
                phone.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            email: decrypt_field(
                &mut crypt,
                "email",
                email.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            ssn: decrypt_field(
                &mut crypt,
                "ssn",
                ssn.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            license_number: decrypt_field(
                &mut crypt,
                "license_number",
                license_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            passport_number: decrypt_field(
                &mut crypt,
                "passport_number",
                passport_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            username: decrypt_field(
                &mut crypt,
                "username",
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        db::EntryData::SecureNote {} => DecryptedData::SecureNote {},
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder,
        name: crypt.decrypt(
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?,
        data,
        fields,
        notes,
        history,
    })
}

pub struct TotpParams {
    pub secret: Vec<u8>,
    pub algorithm: String,
    pub digits: u32,
    pub period: u64,
}

pub fn decode_totp_secret(secret: &str) -> anyhow::Result<Vec<u8>> {
    let secret = secret.trim();
    let alphabets = [
        base32::Alphabet::Rfc4648 { padding: false },
        base32::Alphabet::Rfc4648 { padding: true },
        base32::Alphabet::Rfc4648Lower { padding: false },
        base32::Alphabet::Rfc4648Lower { padding: true },
    ];
    for alphabet in alphabets {
        if let Some(secret) = base32::decode(alphabet, secret) {
            return Ok(secret);
        }
    }
    Err(anyhow::anyhow!("totp secret was not valid base32"))
}

pub fn parse_totp_secret(secret: &str) -> anyhow::Result<TotpParams> {
    if let Ok(u) = url::Url::parse(secret) {
        if u.scheme() != "otpauth" {
            return Err(anyhow::anyhow!(
                "totp secret url must have otpauth scheme"
            ));
        }
        if u.host_str() != Some("totp") {
            return Err(anyhow::anyhow!(
                "totp secret url must have totp host"
            ));
        }
        let query: std::collections::HashMap<_, _> =
            u.query_pairs().collect();
        Ok(TotpParams {
            secret: decode_totp_secret(query
                .get("secret")
                .ok_or_else(|| {
                    anyhow::anyhow!("totp secret url must have secret")
                })?)?,
            algorithm:query.get("algorithm").map_or_else(||{String::from("SHA1")},|alg|{alg.to_string()} ),
            digits: match query.get("digits") {
                Some(dig) => {
                    dig.parse::<u32>().map_err(|_|{
                        anyhow::anyhow!("digits parameter in totp url must be a valid integer.")
                    })?
                }
                None => 6,
            },
            period: match query.get("period") {
                Some(dig) => {
                    dig.parse::<u64>().map_err(|_|{
                        anyhow::anyhow!("period parameter in totp url must be a valid integer.")
                    })?
                }
                None => totp_lite::DEFAULT_STEP,
            }
        })
    } else {
        Ok(TotpParams {
            secret: decode_totp_secret(secret)?,
            algorithm: String::from("SHA1"),
            digits: 6,
            period: totp_lite::DEFAULT_STEP,
        })
    }
}

pub fn generate_totp(secret: &str) -> anyhow::Result<String> {
    let totp_params = parse_totp_secret(secret)?;
    let alg = totp_params.algorithm.as_str();
    match alg {
        "SHA1" => Ok(totp_lite::totp_custom::<totp_lite::Sha1>(
            totp_params.period,
            totp_params.digits,
            &totp_params.secret,
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                .as_secs(),
        )),
        "SHA256" => Ok(totp_lite::totp_custom::<totp_lite::Sha256>(
            totp_params.period,
            totp_params.digits,
            &totp_params.secret,
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                .as_secs(),
        )),
        "SHA512" => Ok(totp_lite::totp_custom::<totp_lite::Sha512>(
            totp_params.period,
            totp_params.digits,
            &totp_params.secret,
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)?
                .as_secs(),
        )),
        _ => Err(anyhow::anyhow!(format!(
            "{} is not a valid totp algorithm",
            alg
        ))),
    }
}

#[derive(Clone, Default)]
pub struct State {
    pub priv_key: Option<locked::Keys>,
    pub org_keys:
        Option<std::collections::HashMap<String, locked::Keys>>,
}

impl State {
    pub fn key(&self, org_id: Option<&str>) -> Option<&locked::Keys> {
        org_id.map_or(self.priv_key.as_ref(), |id| {
            self.org_keys.as_ref().and_then(|h| h.get(id))
        })
    }

    pub fn needs_unlock(&self) -> bool {
        self.priv_key.is_none() || self.org_keys.is_none()
    }
}

impl Cipher for State {
    fn decrypt(
        &mut self,
        cipherstring: &str,
        entry_key: Option<&str>,
        org_id: Option<&str>,
    ) -> anyhow::Result<String> {
        let Some(keys) = self.key(org_id) else {
            return Err(anyhow::anyhow!(
                "failed to find decryption keys in in-memory state"
            ));
        };
        let entry_key = if let Some(entry_key) = entry_key {
            let key_cipherstring =
                CipherString::new(entry_key)
                    .context("failed to parse individual item encryption key")?;
            Some(locked::Keys::new(
                key_cipherstring.decrypt_locked_symmetric(keys).context(
                    "failed to decrypt individual item encryption key",
                )?,
            ))
        } else {
            None
        };
        let cipherstring = CipherString::new(cipherstring)
            .context("failed to parse encrypted secret")?;
        let plaintext = String::from_utf8(
            cipherstring
                .decrypt_symmetric(keys, entry_key.as_ref())
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
        let Some(keys) = self.key(org_id) else {
            return Err(anyhow::anyhow!(
                "failed to find encryption keys in in-memory state"
            ));
        };
        let cipherstring = CipherString::encrypt_symmetric(
            keys,
            plaintext.as_bytes(),
        )
        .context("failed to encrypt plaintext secret")?;

        Ok(cipherstring.to_string())
    }
}
