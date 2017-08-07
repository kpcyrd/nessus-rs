use serde_xml_rs;

pub mod report;
pub mod policy;

#[derive(Debug, Deserialize)]
pub struct NessusClientDatav2 {
    #[serde(rename="Report")]
    pub report: report::Report,
    #[serde(rename="Policy")]
    pub policy: policy::Policy,
}

#[derive(Debug)]
pub enum Error {
    Xml(serde_xml_rs::Error),
}

impl From<serde_xml_rs::Error> for Error {
    fn from(err: serde_xml_rs::Error) -> Error {
        Error::Xml(err)
    }
}

pub fn parse(buffer: String) -> Result<NessusClientDatav2, Error> {
    let report = serde_xml_rs::deserialize(buffer.as_bytes())?;
    Ok(report)
}
