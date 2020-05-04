pub const VERSION: u32 = 3;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Request {
    pub tty: Option<String>,
    pub action: Action,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Action {
    Login,
    Unlock,
    Lock,
    Sync,
    Decrypt {
        cipherstring: String,
        org_id: Option<String>,
    },
    Encrypt {
        plaintext: String,
        org_id: Option<String>,
    },
    Quit,
    Version,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Response {
    Ack,
    Error { error: String },
    Decrypt { plaintext: String },
    Encrypt { cipherstring: String },
    Version { version: u32 },
}
