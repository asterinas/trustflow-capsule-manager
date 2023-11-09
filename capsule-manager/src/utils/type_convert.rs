use crate::error::errors;

pub fn from<T1, T2>(a: &T1) -> Result<T2, errors::Error>
where
    T1: serde::Serialize,
    T2: serde::de::DeserializeOwned,
{
    let content_json = serde_json::to_string(a)?;
    Ok(serde_json::from_str(&content_json)?)
}
