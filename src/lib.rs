//! Nessus Vulnerability Scanner API client
//!
//! ```no_run
//! extern crate nessus;
//!
//! use std::time::Duration;
//! use nessus::VulnScanner;
//!
//! fn main() {
//!     let scan_id = 31337;
//!     let client = nessus::Client::new("https://nessus.example.com", "yourtoken", "secrettoken").unwrap();
//!
//!     let scan = client.launch_scan(scan_id).unwrap();
//!     scan.wait(&client, Duration::from_secs(60), Some(30)).unwrap();
//!
//!     let export = client.export_scan(scan_id).unwrap();
//!     export.wait(&client, Duration::from_secs(3), Some(40)).unwrap();
//!
//!     let report = export.download(&client).unwrap();
//!     println!("download: {:?}", report);
//! }
//! ```
extern crate roadrunner;
extern crate tokio_core;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate serde_xml_rs;
extern crate regex;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate log;
extern crate hyper;
extern crate url;
#[macro_use] extern crate error_chain;

use std::collections::HashMap;
use std::time::Duration;
use std::thread::sleep;

use serde::Serialize;
use serde::de::DeserializeOwned;

use url::Url;
use roadrunner::RestClient;
use roadrunner::RestClientMethods;

/// Nessus reports parser module
pub mod parser;
/// Various structs
pub mod structs;

mod errors {
    use parser;
    use url;
    use roadrunner::{self, Response};

    error_chain! {
        errors {
            Status(r: Response) {
                description("invalid status code")
                display("server sent error: '{:?}'", r)
            }
            WaitTimeout {
                description("wait timeout occured")
                display("task took too long to finish")
            }
        }

        foreign_links {
            RoadRunner(roadrunner::Error);
            Url(url::ParseError);
            Parser(parser::Error);
        }
    }
}
pub use errors::*;

/// Nessus API client
#[derive(Debug)]
pub struct Client {
    host: Url,
    token: String,
    secret: String,
}

pub trait VulnScanner {
    fn list_policies(&self) -> Result<structs::PolicyReponse>;

    fn create_scan(&self, template_uuid: &str, settings: structs::ScanSettings) -> Result<structs::CreateScanResponse>;

    fn configure_scan(&self, scan_id: u64, template_uuid: Option<String>, settings: structs::ScanSettingsUpdate) -> Result<structs::UpdateScanResponse>;

    fn delete_history(&self, scan_id: u64, history_id: u64) -> Result<()>;

    fn delete_scan(&self, scan_id: u64) -> Result<()>;

    fn launch_scan(&self, id: u64) -> Result<structs::ScanLaunchResponse>;

    fn stop_scan(&self, id: u64) -> Result<()>;

    fn pause_scan(&self, id: u64) -> Result<()>;

    fn resume_scan(&self, id: u64) -> Result<()>;

    fn scan_details(&self, id: u64) -> Result<structs::ScanDetails>;

    fn list_scans(&self) -> Result<structs::ScanListResponse>;

    fn list_scan_folder(&self, id: u64) -> Result<structs::ScanListResponse>;

    fn export_scan(&self, scan_id: u64) -> Result<structs::ExportToken>;

    fn export_status(&self, scan_id: u64, file_id: u64) -> Result<structs::ExportStatus>;

    fn download_export_raw(&self, scan_id: u64, file_id: u64) -> Result<String>;

    fn download_export(&self, scan_id: u64, file_id: u64) -> Result<parser::NessusClientDatav2>;
}

impl Client {
    pub fn new<I: Into<String>>(host: &str, token: I, secret: I) -> Result<Client> {
        Ok(Client {
            host: Url::parse(host)?,
            token: token.into(),
            secret: secret.into(),
        })
    }

    #[inline]
    fn deserialize<T: DeserializeOwned>(&self, response: roadrunner::Response) -> Result<T> {
        info!("Response: {:?}", response);

        let obj = response.content().as_typed()?;
        Ok(obj)
    }

    #[inline]
    fn assure_ok(response: roadrunner::Response) -> Result<roadrunner::Response> {
        let is_ok = {
            let status = response.status();
            *status == hyper::StatusCode::Ok || *status == hyper::StatusCode::Created
        };

        if ! is_ok {
            Err(Error::from(ErrorKind::Status(response)))
        } else {
            Ok(response)
        }
    }

    #[inline]
    fn mkurl(&self, path: &str) -> Result<Url> {
        Ok(self.host.join(path)?)
    }

    #[inline]
    fn raw_get(&self, path: &str) -> Result<roadrunner::Response> {
        let mut core = tokio_core::reactor::Core::new().unwrap();

        let response = RestClient::get(self.mkurl(path)?.as_str())
            .header_append_raw("X-ApiKeys", format!("accessKey={}; secretKey={}", self.token, self.secret))
            .execute_on(&mut core)?;

        Client::assure_ok(response)
    }

    #[inline]
    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let x = self.raw_get(path)?;
        self.deserialize(x)
    }

    #[inline]
    fn post_empty<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let mut core = tokio_core::reactor::Core::new().unwrap();

        let response = RestClient::post(self.mkurl(path)?.as_str())
            .header_append_raw("X-ApiKeys", format!("accessKey={}; secretKey={}", self.token, self.secret))
            .execute_on(&mut core)?;

        self.deserialize(Client::assure_ok(response)?)
    }

    #[inline]
    fn post<T: Serialize, R: DeserializeOwned>(&self, path: &str, msg: T) -> Result<R> {
        let mut core = tokio_core::reactor::Core::new().unwrap();

        let response = RestClient::post(self.mkurl(path)?.as_str())
            .header_append_raw("X-ApiKeys", format!("accessKey={}; secretKey={}", self.token, self.secret))
            .json_body_typed(&msg)
            .execute_on(&mut core)?;

        self.deserialize(Client::assure_ok(response)?)
    }

    #[inline]
    fn put<T: Serialize, R: DeserializeOwned>(&self, path: &str, msg: T) -> Result<R> {
        let mut core = tokio_core::reactor::Core::new().unwrap();

        let response = RestClient::put(self.mkurl(path)?.as_str())
            .header_append_raw("X-ApiKeys", format!("accessKey={}; secretKey={}", self.token, self.secret))
            .json_body_typed(&msg)
            .execute_on(&mut core)?;

        self.deserialize(Client::assure_ok(response)?)
    }

    #[inline]
    fn raw_delete(&self, path: &str) -> Result<roadrunner::Response> {
        let mut core = tokio_core::reactor::Core::new().unwrap();

        let response = RestClient::get(self.mkurl(path)?.as_str())
            .header_append_raw("X-ApiKeys", format!("accessKey={}; secretKey={}", self.token, self.secret))
            .execute_on(&mut core)?;

        Client::assure_ok(response)
    }
}

impl VulnScanner for Client {
    fn list_policies(&self) -> Result<structs::PolicyReponse> {
        self.get("/editor/policy/templates")
    }

    fn create_scan(&self, template_uuid: &str, settings: structs::ScanSettings) -> Result<structs::CreateScanResponse> {
        let request = structs::CreateScanRequest {
            uuid: template_uuid.into(),
            settings: settings,
        };
        let scan: structs::CreateScanResponse = self.post("/scans", request)?;
        Ok(scan)
    }

    fn configure_scan(&self, scan_id: u64, template_uuid: Option<String>, settings: structs::ScanSettingsUpdate) -> Result<structs::UpdateScanResponse> {
        let request = structs::UpdateScanRequest {
            uuid: template_uuid,
            settings: settings,
        };

        let scan: structs::UpdateScanResponse = self.put(&format!("/scans/{}", scan_id), request)?;
        Ok(scan)
    }

    fn delete_history(&self, scan_id: u64, history_id: u64) -> Result<()> {
        self.raw_delete(&format!("/scans/{}/history/{}", scan_id, history_id))?;
        Ok(())
    }

    fn delete_scan(&self, scan_id: u64) -> Result<()> {
        self.raw_delete(&format!("/scans/{}", scan_id))?;
        Ok(())
    }

    fn launch_scan(&self, id: u64) -> Result<structs::ScanLaunchResponse> {
        let mut launch: structs::ScanLaunchResponse = self.post_empty(&format!("/scans/{}/launch", id))?;

        launch.scan_id = Some(id);
        Ok(launch)
    }

    fn stop_scan(&self, id: u64) -> Result<()> {
        self.post_empty(&format!("/scans/{}/stop", id))
    }

    fn pause_scan(&self, id: u64) -> Result<()> {
        self.post_empty(&format!("/scans/{}/pause", id))
    }

    fn resume_scan(&self, id: u64) -> Result<()> {
        self.post_empty(&format!("/scans/{}/resume", id))
    }

    fn scan_details(&self, id: u64) -> Result<structs::ScanDetails> {
        self.get(&format!("/scans/{}", id))
    }

    fn list_scans(&self) -> Result<structs::ScanListResponse> {
        self.get("/scans")
    }

    fn list_scan_folder(&self, id: u64) -> Result<structs::ScanListResponse> {
        // TODO: use ?folder_id=
        let response = self.list_scans()?;

        let folders = response.folders.into_iter()
                        .filter(|x| x.id == id)
                        .collect();
        let scans = response.scans.into_iter()
                        .filter(|x| x.folder_id == id)
                        .collect();

        Ok(structs::ScanListResponse {
            folders,
            scans,
            timestamp: response.timestamp,
        })
    }

    fn export_scan(&self, scan_id: u64) -> Result<structs::ExportToken> {
        let mut x = HashMap::new();
        x.insert("format", "nessus");

        let mut token: structs::ExportToken = self.post(&format!("/scans/{}/export", scan_id), x)?;
        token.scan_id = Some(scan_id);
        Ok(token)
    }

    fn export_status(&self, scan_id: u64, file_id: u64) -> Result<structs::ExportStatus> {
        self.get(&format!("/scans/{}/export/{}/status", scan_id, file_id))
    }

    fn download_export_raw(&self, scan_id: u64, file_id: u64) -> Result<String> {
        let response = self.raw_get(&format!("/scans/{}/export/{}/download", scan_id, file_id))?;
        let content = response.content();
        let string = content.as_ref_string().to_owned();
        Ok(string)
    }

    fn download_export(&self, scan_id: u64, file_id: u64) -> Result<parser::NessusClientDatav2> {
        let response = self.download_export_raw(scan_id, file_id)?;
        let report = parser::parse(response)?;
        Ok(report)
    }
}

pub trait Waitable<V: VulnScanner> {
    fn is_pending(&self, client: &V) -> Result<bool>;

    fn wait(&self, client: &V, interval: Duration, mut max_attempts: Option<u64>) -> Result<()> {
        loop {
            if ! self.is_pending(&client)? {
                return Ok(());
            }

            if let Some(ref mut left) = max_attempts {
                if *left <= 0 {
                    break;
                }

                *left -= 1;
            }

            sleep(interval);
        }

        return Err(Error::from(ErrorKind::WaitTimeout));
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
