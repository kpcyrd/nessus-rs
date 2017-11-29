#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Report {
    pub name: String,
    #[serde(rename="ReportHost", default)]
    pub report_hosts: Vec<ReportHost>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReportHost {
    pub name: String,
    #[serde(rename="HostProperties")]
    pub host_properties: HostProperties,
    #[serde(rename="ReportItem")]
    pub report_items: Vec<ReportItem>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostProperties {
    #[serde(rename="tag")]
    pub tags: Vec<Tag>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Tag {
    pub name: String,
    #[serde(rename="$value")]
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReportItem {
    pub port: String,
    pub svc_name: String,
    pub protocol: String,
    pub severity: String, // set to u64 after https://github.com/RReverser/serde-xml-rs/issues/25
    #[serde(rename="pluginID")]
    pub plugin_id: String,
    #[serde(rename="pluginName")]
    pub plugin_name: String,
    #[serde(rename="pluginFamily")]
    pub plugin_family: String,

    pub description: String,
    pub fname: String,
    pub plugin_modification_date: String,
    pub plugin_publication_date: String,
    pub plugin_type: String,
    pub risk_factor: String,
    pub script_version: String,
    pub solution: String,
    pub synopsis: String,
    pub plugin_output: Option<String>,
}
