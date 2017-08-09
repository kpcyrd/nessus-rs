extern crate roadrunner;
extern crate tokio_core;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate serde_xml_rs;
#[macro_use] extern crate log;
extern crate hyper;

use std::collections::HashMap;
use std::time::Duration;
use std::thread::sleep;

use serde::Serialize;
use serde::de::DeserializeOwned;

use roadrunner::RestClient;
use roadrunner::RestClientMethods;

mod error;
pub mod parser;
pub mod structs;

pub use error::Error;

/// Nessus API client
#[derive(Debug)]
pub struct Client {
    host: String,
    token: String,
    secret: String,
}

impl Client {
    pub fn new(host: String, token: String, secret: String) -> Client {
        Client {
            host,
            token,
            secret,
        }
    }

    fn deserialize<T: DeserializeOwned>(&self, response: roadrunner::Response) -> Result<T, Error> {
        info!("Response: {:?}", response);

        let obj = response.content().as_typed()?;
        Ok(obj)
    }

    fn assure_ok(response: roadrunner::Response) -> Result<roadrunner::Response, Error> {
        let status = response.status().clone();

        if status != hyper::StatusCode::Ok && status != hyper::StatusCode::Created {
            Err(Error::Status(response))
        } else {
            Ok(response)
        }
    }

    fn raw_get(&self, url: &str) -> Result<roadrunner::Response, Error> {
        let mut core = tokio_core::reactor::Core::new().unwrap();

        let response = RestClient::get(&format!("{}{}", self.host, url))
            .header_append_raw("X-ApiKeys", format!("accessKey={}; secretKey={}", self.token, self.secret))
            .execute_on(&mut core)?;

        Client::assure_ok(response)
    }

    fn get<T: DeserializeOwned>(&self, url: &str) -> Result<T, Error> {
        let mut core = tokio_core::reactor::Core::new().unwrap();

        let response = RestClient::get(&format!("{}{}", self.host, url))
            .header_append_raw("X-ApiKeys", format!("accessKey={}; secretKey={}", self.token, self.secret))
            .execute_on(&mut core)?;

        self.deserialize(Client::assure_ok(response)?)
    }

    fn post_empty<T: DeserializeOwned>(&self, url: &str) -> Result<T, Error> {
        let mut core = tokio_core::reactor::Core::new().unwrap();

        let response = RestClient::post(&format!("{}{}", self.host, url))
            .header_append_raw("X-ApiKeys", format!("accessKey={}; secretKey={}", self.token, self.secret))
            .execute_on(&mut core)?;

        self.deserialize(Client::assure_ok(response)?)
    }

    fn post<T: Serialize, R: DeserializeOwned>(&self, url: &str, msg: T) -> Result<R, Error> {
        let mut core = tokio_core::reactor::Core::new().unwrap();

        let response = RestClient::post(&format!("{}{}", self.host, url))
            .header_append_raw("X-ApiKeys", format!("accessKey={}; secretKey={}", self.token, self.secret))
            .json_body_typed(&msg)
            .execute_on(&mut core)?;

        self.deserialize(Client::assure_ok(response)?)
    }

    pub fn list_policies(&self) -> Result<structs::PolicyReponse, Error> {
        self.get("/editor/policy/templates")
    }

    pub fn launch_scan(&self, id: u64) -> Result<structs::ScanLaunchResponse, Error> {
        let mut launch: structs::ScanLaunchResponse = self.post_empty(&format!("/scans/{}/launch", id))?;

        launch.scan_id = Some(id);
        Ok(launch)
    }

    pub fn stop_scan(&self, id: u64) -> Result<(), Error> {
        self.post_empty(&format!("/scans/{}/stop", id))
    }

    pub fn pause_scan(&self, id: u64) -> Result<(), Error> {
        self.post_empty(&format!("/scans/{}/pause", id))
    }

    pub fn resume_scan(&self, id: u64) -> Result<(), Error> {
        self.post_empty(&format!("/scans/{}/resume", id))
    }

    pub fn scan_details(&self, id: u64) -> Result<structs::ScanDetails, Error> {
        self.get(&format!("/scans/{}", id))
    }

    pub fn list_scans(&self) -> Result<structs::ScanListResponse, Error> {
        self.get("/scans")
    }

    pub fn list_scan_folder(&self, id: u64) -> Result<structs::ScanListResponse, Error> {
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

    pub fn export_scan(&self, scan_id: u64) -> Result<structs::ExportToken, Error> {
        let mut x = HashMap::new();
        x.insert("format", "nessus");

        let mut token: structs::ExportToken = self.post(&format!("/scans/{}/export", scan_id), x)?;
        token.scan_id = Some(scan_id);
        Ok(token)
    }

    pub fn export_status(&self, scan_id: u64, file_id: u64) -> Result<structs::ExportStatus, Error> {
        self.get(&format!("/scans/{}/export/{}/status", scan_id, file_id))
    }

    pub fn download_export_raw(&self, scan_id: u64, file_id: u64) -> Result<String, Error> {
        let response = self.raw_get(&format!("/scans/{}/export/{}/download", scan_id, file_id))?;
        let content = response.content();
        let string = content.as_ref_string().to_owned();
        Ok(string)
    }

    pub fn download_export(&self, scan_id: u64, file_id: u64) -> Result<parser::NessusClientDatav2, Error> {
        let response = self.download_export_raw(scan_id, file_id)?;
        let report = parser::parse(response)?;
        Ok(report)
    }
}

trait Waitable {
    fn is_pending(&self, client: &Client) -> Result<bool, Error>;

    fn wait(&self, client: &Client, interval: Duration, mut max_attempts: Option<u64>) -> Result<(), Error> {
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

        return Err(Error::WaitTimeout);
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
