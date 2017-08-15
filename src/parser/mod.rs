use serde_xml_rs;
use regex::Regex;

pub mod report;
pub mod policy;

/// Parsed nessus report
#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PatchAdvice {
    old_version: String,
    new_version: String,
    severity: u64,
}

impl PatchAdvice {
    pub fn new<I: Into<String>>(old_version: I, new_version: I, severity: u64) -> PatchAdvice {
        PatchAdvice {
            old_version: old_version.into(),
            new_version: new_version.into(),
            severity: severity,
        }
    }
}

impl report::ReportItem {
    pub fn patch_needed(&self) -> Option<Vec<PatchAdvice>> {
        lazy_static! {
            static ref RE: Vec<Regex> = vec![
                // debian
                Regex::new("Remote package installed : (?P<old>.*)\nShould be : (?P<new>.*)").unwrap(),
                // java
                Regex::new("The following vulnerable instance of Java is installed on the\nremote host :\n\n  Path              : (?P<path>.*)\n  Installed version : (?P<old>.*)\n  Fixed version     : (?P<new>.*)").unwrap(),
                // ubuntu
                Regex::new("- Installed package : (?P<old>.*)\n    Fixed package     : (?P<new>.*)").unwrap(),
            ];
        }

        match self.plugin_output {
            Some(ref output) => {
                let advice: Vec<PatchAdvice> = RE.iter()
                    .flat_map(|re| {
                        re.captures_iter(output)
                    })
                    .map(|caps| {
                        PatchAdvice {
                            old_version: caps["old"].to_owned(),
                            new_version: caps["new"].to_owned(),
                            severity: self.severity.parse().unwrap(), // set to u64 after https://github.com/RReverser/serde-xml-rs/issues/25
                        }
                    })
                    .collect();

                if advice.len() > 0 {
                    Some(advice)
                } else {
                    None
                }
            },
            None => None
        }
    }
}

impl report::ReportHost {
    pub fn patch_needed(&self) -> Option<Vec<PatchAdvice>> {
        let advice: Vec<PatchAdvice> = self.report_items.iter()
            .flat_map(|item| {
                match item.patch_needed() {
                    Some(advice) => advice,
                    None => Vec::new(),
                }
            })
            .collect();

        if advice.len() > 0 {
            Some(advice)
        } else {
            None
        }
    }
}


#[cfg(test)]
mod tests {
    use super::parse;
    use super::PatchAdvice;
    use super::report::ReportItem;

    #[test]
    fn test_parse() {
        let reports = vec![
            ("nessus_report_local2.nessus", include_str!("../../files/nessus_report_local2.nessus")),
            ("nessus_report_local_3.nessus", include_str!("../../files/nessus_report_local_3.nessus")),
            ("nessus_report_localpci.nessus", include_str!("../../files/nessus_report_localpci.nessus")),
            ("nessus_report_test_local.nessus", include_str!("../../files/nessus_report_test_local.nessus")),
        ];

        for (name, report) in reports {
            let report = parse(report);
            println!("report {:?}: {:?}", name, report);
            assert!(report.is_ok());
        }
    }

    #[test]
    fn test_debian_patch_advice() {
        let item = ReportItem {
            port: "0".to_owned(),
            svc_name: "general".to_owned(),
            protocol: "tcp".to_owned(),
            severity: "3".to_owned(),
            plugin_id: "101322".to_owned(),
            plugin_name: "Debian DSA-3904-1 : bind9 - security update".to_owned(),
            plugin_family: "Debian Local Security Checks".to_owned(),
            description: "Clement Berthaux from Synaktiv discovered two vulnerabilities in BIND, a DNS server implementation. They allow an attacker to bypass TSIG authentication by sending crafted DNS packets to a server.\n\n  - CVE-2017-3142     An attacker who is able to send and receive messages to     an authoritative DNS server and who has knowledge of a     valid TSIG key name may be able to circumvent TSIG     authentication of AXFR requests via a carefully     constructed request packet. A server that relies solely     on TSIG keys for protection with no other ACL protection     could be manipulated into :\n\n    - providing an AXFR of a zone to an unauthorized       recipient\n    - accepting bogus NOTIFY packets\n\n  - CVE-2017-3143     An attacker who is able to send and receive messages to     an authoritative DNS server and who has knowledge of a     valid TSIG key name for the zone and service being     targeted may be able to manipulate BIND into accepting     an unauthorized dynamic update.".to_owned(),
            fname: "debian_DSA-3904.nasl".to_owned(),
            plugin_modification_date: "2017/07/12".to_owned(),
            plugin_publication_date: "2017/07/10".to_owned(),
            plugin_type: "local".to_owned(),
            risk_factor: "High".to_owned(),
            script_version: "$Revision: 3.3 $".to_owned(),
            solution: "Upgrade the bind9 packages.\n\nFor the oldstable distribution (jessie), these problems have been fixed in version 1:9.9.5.dfsg-9+deb8u12.\n\nFor the stable distribution (stretch), these problems have been fixed in version 1:9.10.3.dfsg.P4-12.3+deb9u1.".to_owned(),
            synopsis: "The remote Debian host is missing a security-related update.".to_owned(),
            plugin_output: Some("Remote package installed : bind9-host_1:9.9.5.dfsg-9+deb8u11\nShould be : bind9-host_1:9.9.5.dfsg-9+deb8u12\nRemote package installed : dnsutils_1:9.9.5.dfsg-9+deb8u11\nShould be : dnsutils_1:9.9.5.dfsg-9+deb8u12\nRemote package installed : libbind9-90_1:9.9.5.dfsg-9+deb8u11\nShould be : libbind9-90_1:9.9.5.dfsg-9+deb8u12\nRemote package installed : libdns-export100_1:9.9.5.dfsg-9+deb8u11\nShould be : libdns-export100_1:9.9.5.dfsg-9+deb8u12\nRemote package installed : libdns100_1:9.9.5.dfsg-9+deb8u11\nShould be : libdns100_1:9.9.5.dfsg-9+deb8u12\nRemote package installed : libirs-export91_1:9.9.5.dfsg-9+deb8u11\nShould be : libirs-export91_1:9.9.5.dfsg-9+deb8u12\nRemote package installed : libisc-export95_1:9.9.5.dfsg-9+deb8u11\nShould be : libisc-export95_1:9.9.5.dfsg-9+deb8u12\nRemote package installed : libisc95_1:9.9.5.dfsg-9+deb8u11\nShould be : libisc95_1:9.9.5.dfsg-9+deb8u12\nRemote package installed : libisccc90_1:9.9.5.dfsg-9+deb8u11\nShould be : libisccc90_1:9.9.5.dfsg-9+deb8u12\nRemote package installed : libisccfg-export90_1:9.9.5.dfsg-9+deb8u11\nShould be : libisccfg-export90_1:9.9.5.dfsg-9+deb8u12\nRemote package installed : libisccfg90_1:9.9.5.dfsg-9+deb8u11\nShould be : libisccfg90_1:9.9.5.dfsg-9+deb8u12\nRemote package installed : liblwres90_1:9.9.5.dfsg-9+deb8u11\nShould be : liblwres90_1:9.9.5.dfsg-9+deb8u12".to_owned())
        };

        let patch_advice = item.patch_needed();
        assert_eq!(patch_advice, Some(vec![
            PatchAdvice::new("bind9-host_1:9.9.5.dfsg-9+deb8u11", "bind9-host_1:9.9.5.dfsg-9+deb8u12", 3),
            PatchAdvice::new("dnsutils_1:9.9.5.dfsg-9+deb8u11", "dnsutils_1:9.9.5.dfsg-9+deb8u12", 3),
            PatchAdvice::new("libbind9-90_1:9.9.5.dfsg-9+deb8u11", "libbind9-90_1:9.9.5.dfsg-9+deb8u12", 3),
            PatchAdvice::new("libdns-export100_1:9.9.5.dfsg-9+deb8u11", "libdns-export100_1:9.9.5.dfsg-9+deb8u12", 3),
            PatchAdvice::new("libdns100_1:9.9.5.dfsg-9+deb8u11", "libdns100_1:9.9.5.dfsg-9+deb8u12", 3),
            PatchAdvice::new("libirs-export91_1:9.9.5.dfsg-9+deb8u11", "libirs-export91_1:9.9.5.dfsg-9+deb8u12", 3),
            PatchAdvice::new("libisc-export95_1:9.9.5.dfsg-9+deb8u11", "libisc-export95_1:9.9.5.dfsg-9+deb8u12", 3),
            PatchAdvice::new("libisc95_1:9.9.5.dfsg-9+deb8u11", "libisc95_1:9.9.5.dfsg-9+deb8u12", 3),
            PatchAdvice::new("libisccc90_1:9.9.5.dfsg-9+deb8u11", "libisccc90_1:9.9.5.dfsg-9+deb8u12", 3),
            PatchAdvice::new("libisccfg-export90_1:9.9.5.dfsg-9+deb8u11", "libisccfg-export90_1:9.9.5.dfsg-9+deb8u12", 3),
            PatchAdvice::new("libisccfg90_1:9.9.5.dfsg-9+deb8u11", "libisccfg90_1:9.9.5.dfsg-9+deb8u12", 3),
            PatchAdvice::new("liblwres90_1:9.9.5.dfsg-9+deb8u11", "liblwres90_1:9.9.5.dfsg-9+deb8u12", 3)
        ]));
    }
}
