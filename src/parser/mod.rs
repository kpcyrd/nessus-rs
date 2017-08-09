use serde_xml_rs;

pub mod report;
pub mod policy;

/// Parsed nessus report
#[derive(Debug, Deserialize)]
pub struct NessusClientDatav2 {
    #[serde(rename="Report")]
    pub report: report::Report,
    #[serde(rename="Policy")]
    pub policy: policy::Policy,
}

/// A set of errors that can occur
#[derive(Debug)]
pub enum Error {
    Xml(serde_xml_rs::Error),
}

impl From<serde_xml_rs::Error> for Error {
    fn from(err: serde_xml_rs::Error) -> Error {
        Error::Xml(err)
    }
}

/// Parse Nessus Reports
pub fn parse<I: Into<String>>(buffer: I) -> Result<NessusClientDatav2, Error> {
    let report = serde_xml_rs::deserialize(buffer.into().as_bytes())?;
    Ok(report)
}
