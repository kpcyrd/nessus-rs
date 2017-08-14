#[derive(Debug, Deserialize, Serialize)]
pub struct Policy {
    #[serde(rename="Preferences")]
    pub preferences: Preferences,
    #[serde(rename="FamilySelection")]
    pub family_selection: FamilySelection,
    #[serde(rename="IndividualPluginSelection")]
    pub individual_plugin_selection: IndividualPluginSelection,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Preferences {
    #[serde(rename="ServerPreferences")]
    pub server_preferences: ServerPreferences,
    #[serde(rename="PluginsPreferences")]
    pub plugins_preferences: PluginsPreferences,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerPreferences {
    #[serde(rename="preference")]
    pub preferences: Vec<ServerPreference>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerPreference {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PluginsPreferences {
    #[serde(rename="item")]
    pub preferences: Vec<PluginPreference>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PluginPreference {
    #[serde(rename="pluginName")]
    pub plugin_name: String,
    #[serde(rename="pluginId", with="u64")]
    pub plugin_id: u64,
    #[serde(rename="fullName")]
    pub full_name: String,
    #[serde(rename="preferenceName")]
    pub preference_name: String,
    #[serde(rename="preferenceType")]
    pub preference_type: String,
    #[serde(rename="preferenceValues")]
    pub preference_values: String,
    #[serde(rename="selectedValue")]
    pub selected_value: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FamilySelection {
    #[serde(rename="FamilyItem")]
    pub family_items: Vec<FamilyItem>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FamilyItem {
    #[serde(rename="FamilyName")]
    pub family_name: String,
    #[serde(rename="Status")]
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IndividualPluginSelection {
    #[serde(rename="PluginItem")]
    pub plugin_items: Vec<PluginItem>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PluginItem {
    #[serde(rename="PluginId", with="u64")]
    pub plugin_id: u64,
    #[serde(rename="PluginName")]
    pub plugin_name: String,
    #[serde(rename="Family")]
    pub family: String,
    #[serde(rename="Status")]
    pub status: String,
}
