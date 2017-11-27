use std::time::Duration;

use Client;
use Error;
use parser;
use Waitable;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PolicyReponse {
    pub templates: Vec<Policy>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Policy {
    pub desc: String,
    pub title: String,
    pub name: String,
    pub subscription_only: bool,
    pub uuid: String,
    pub cloud_only: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CreateScanRequest {
    pub uuid: String,
    pub settings: ScanSettings,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CreateScanResponse {
    pub uuid: String,
    // TODO: settings
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ScanSettings {
    /// The name of the scan
    pub name: String,
    /// The description of the scan
    pub description: Option<String>,
    /// The unique id of the policy to use
    pub policy_id: Option<u32>,
    /// The unique id of the destination folder for the scan
    pub folder_id: Option<u32>,
    /// The unique id of the scanner to use
    pub scanner_id: Option<u32>,
    /// If true, the schedule for the scan is enabled
    pub enabled: bool,
    /// When to launch the scan. (i.e. ON_DEMAND, DAILY, WEEKLY, MONTHLY, YEARLY)
    pub launch: Option<String>,
    /// The starting time and date for the scan (i.e. YYYYMMDDTHHMMSS)
    pub starttime: Option<String>,
    /// Expects a semi-colon delimited string comprised of three values. The frequency (FREQ=ONCE or DAILY or WEEKLY or MONTHLY or YEARLY), the interval (INTERVAL=1 or 2 or 3 ... x), and the days of the week (BYDAY=SU,MO,TU,WE,TH,FR,SA). To create a scan that runs every three weeks on Monday Wednesday and Friday the string would be 'FREQ=WEEKLY;INTERVAL=3;BYDAY=MO,WE,FR'
    pub rrules: Option<String>,
    /// The timezone for the scan schedule
    pub timezone: Option<String>,
    /// The list of targets to scan
    pub text_targets: String,
    /// The name of a file containing the list of targets to scan
    pub file_targets: Option<String>,
    /// A comma separated list of accounts who will recieve the email summary report
    pub emails: Option<String>,
    // /// An array containing permissions to apply to the scan
    // pub acls: Option<Vec<String>>>, // type isn't documented
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UpdateScanRequest {
    pub uuid: Option<String>,
    pub settings: ScanSettingsUpdate,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UpdateScanResponse {
    pub uuid: String,
    // TODO: settings
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ScanSettingsUpdate {
    /// The name of the scan
    pub name: Option<String>,
    /// The description of the scan
    pub description: Option<String>,
    /// The unique id of the policy to use
    pub policy_id: Option<u32>,
    /// The unique id of the destination folder for the scan
    pub folder_id: Option<u32>,
    /// The unique id of the scanner to use
    pub scanner_id: Option<u32>,
    /// If true, the schedule for the scan is enabled
    pub enabled: bool,
    /// When to launch the scan. (i.e. ON_DEMAND, DAILY, WEEKLY, MONTHLY, YEARLY)
    pub launch: Option<String>,
    /// The starting time and date for the scan (i.e. YYYYMMDDTHHMMSS)
    pub starttime: Option<String>,
    /// Expects a semi-colon delimited string comprised of three values. The frequency (FREQ=ONCE or DAILY or WEEKLY or MONTHLY or YEARLY), the interval (INTERVAL=1 or 2 or 3 ... x), and the days of the week (BYDAY=SU,MO,TU,WE,TH,FR,SA). To create a scan that runs every three weeks on Monday Wednesday and Friday the string would be 'FREQ=WEEKLY;INTERVAL=3;BYDAY=MO,WE,FR'
    pub rrules: Option<String>,
    /// The timezone for the scan schedule
    pub timezone: Option<String>,
    // /// An array of target group IDs to scan
    // pub target_groups: Option<Vec<u32>>,
    // /// An array An array of agent group IDs to scan. Required if the scan is an agent scan
    // pub agent_groups: Option<Vec<u32>>,
    /// The list of targets to scan
    pub text_targets: String,
    /// The name of a file containing the list of targets to scan
    pub file_targets: Option<String>,
    /// A comma separated list of accounts who will recieve the email summary report
    pub emails: Option<String>,
    // /// An array containing permissions to apply to the scan
    // pub acls: Option<Vec<String>>>, // type isn't documented
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ScanListResponse {
    pub folders: Vec<Folder>,
    pub scans: Vec<Scan>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Folder {
    pub unread_count: Option<u32>,
    pub custom: u32,
    pub default_tag: u32,
    #[serde(rename="type")]
    pub folder_type: String,
    pub name: String,
    pub id: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ScanDetails {
    pub info: ScanDetailsInfo,
    #[serde(default)]
    pub hosts: Vec<ScanDetailsHost>,
    #[serde(default)]
    pub comphosts: Vec<ScanDetailsHost>,
    #[serde(default)]
    pub vulnerabilities: Vec<ScanDetailsVulnerability>,
    #[serde(default)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ScanDetailsInfo {
    // pub acls
    pub edit_allowed: Option<bool>,
    pub status: String,
    pub policy: Option<String>,
    #[serde(rename="pci-can-upload")]
    pub pci_can_upload: Option<bool>,
    pub hasaudittrail: Option<bool>,
    pub scan_start: Option<u64>,
    pub folder_id: u64,
    pub targets: Option<String>,
    pub timestamp: Option<u64>,
    pub object_id: u64,
    pub scanner_name: String,
    pub haskb: Option<bool>,
    pub uuid: Option<String>,
    pub hostcount: Option<u64>,
    pub name: String,
    pub user_permissions: u64,
    pub control: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ScanDetailsVulnerability {
    pub plugin_id: u64,
    pub plugin_name: String,
    pub plugin_family: String,
    pub count: u64,
    pub vuln_index: Option<u64>,
    pub severity_index: u64,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ExportStatus {
    pub status: String,
}

impl ExportStatus {
    pub fn is_ready(&self) -> bool {
        self.status == "ready"
    }
}
