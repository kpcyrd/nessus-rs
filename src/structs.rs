use std::time::Duration;

use Client;
use Error;
use parser;
use Waitable;

#[derive(Debug, Deserialize, Serialize)]
pub struct PolicyReponse {
    pub templates: Vec<Policy>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Policy {
    pub desc: String,
    pub title: String,
    pub name: String,
    pub subscription_only: bool,
    pub uuid: String,
    pub cloud_only: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanLaunchResponse {
    pub scan_uuid: String,

    pub scan_id: Option<u64>, // added by nessus-rs
}

impl ScanLaunchResponse {
    pub fn wait(&self, client: &Client, interval: Duration, max_attempts: Option<u64>) -> Result<(), Error> {
        <ScanLaunchResponse as Waitable>::wait(self, client, interval, max_attempts)
    }
}

impl Waitable for ScanLaunchResponse {
    fn is_pending(&self, client: &Client) -> Result<bool, Error> {
        let details = client.scan_details(self.scan_id.unwrap())?;
        Ok(details.is_running())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanListResponse {
    pub folders: Vec<Folder>,
    pub scans: Vec<Scan>,
    pub timestamp: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Folder {
    pub unread_count: Option<u32>,
    pub custom: u32,
    pub default_tag: u32,
    #[serde(rename="type")]
    pub folder_type: String,
    pub name: String,
    pub id: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Scan {
    pub folder_id: u64,
    pub read: bool,
    pub last_modification_date: u64,
    pub creation_date: u64,
    pub status: String,
    pub uuid: Option<String>,
    pub shared: bool,
    pub user_permissions: u64,
    pub owner: String,
    pub timezone: Option<String>,
    pub rrules: Option<String>,
    pub starttime: Option<String>,
    pub control: bool,
    pub name: String,
    pub id: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanDetails {
    pub info: ScanDetailsInfo,
    pub hosts: Vec<ScanDetailsHost>,
    pub comphosts: Vec<ScanDetailsHost>,
    pub vulnerabilities: Vec<ScanDetailsVulnerability>,
    pub compliance: Vec<ScanDetailsVulnerability>,
}

impl ScanDetails {
    pub fn is_complete(&self) -> bool {
        self.info.status == "complete"
    }

    pub fn is_running(&self) -> bool {
        self.info.status == "running"
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanDetailsInfo {
    // pub acls
    pub edit_allowed: bool,
    pub status: String,
    pub policy: Option<String>,
    #[serde(rename="pci-can-upload")]
    pub pci_can_upload: bool,
    pub hasaudittrail: bool,
    pub scan_start: u64,
    pub folder_id: u64,
    pub targets: Option<String>,
    pub timestamp: u64,
    pub object_id: u64,
    pub scanner_name: String,
    pub haskb: bool,
    pub uuid: String,
    pub hostcount: u64,
    pub name: String,
    pub user_permissions: u64,
    pub control: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanDetailsHost {
    pub host_id: u64,
    pub host_index: u64,
    pub hostname: String,
    pub progress: String,
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
    pub totalchecksconsidered: u64,
    pub numchecksconsidered: u64,
    pub scanprogresstotal: u64,
    pub scanprogresscurrent: u64,
    pub score: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanDetailsVulnerability {
    pub plugin_id: u64,
    pub plugin_name: String,
    pub plugin_family: String,
    pub count: u64,
    pub vuln_index: u64,
    pub severity_index: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ExportToken {
    pub file: u64,
    pub token: String,

    pub scan_id: Option<u64>, // added by nessus-rs
}

impl ExportToken {
    pub fn wait(&self, client: &Client, interval: Duration, max_attempts: Option<u64>) -> Result<(), Error> {
        <ExportToken as Waitable>::wait(self, client, interval, max_attempts)
    }

    pub fn download(&self, client: &Client) -> Result<parser::NessusClientDatav2, Error> {
        client.download_export(self.scan_id.unwrap(), self.file)
    }
}

impl Waitable for ExportToken {
    fn is_pending(&self, client: &Client) -> Result<bool, Error> {
        let status = client.export_status(self.scan_id.unwrap(), self.file)?;
        Ok(!status.is_ready())
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ExportStatus {
    pub status: String,
}

impl ExportStatus {
    pub fn is_ready(&self) -> bool {
        self.status == "ready"
    }
}
