use anyhow::{bail, Result};
use reqwest::blocking::multipart::{Form, Part};
use reqwest::blocking::Client;
use reqwest::blocking::ClientBuilder;
use serde::{Deserialize, Serialize};
use std::env::args;
use std::fs::File;
use std::io::Read;

#[derive(Serialize)]
struct LoginRequest<'a> {
    username: &'a str,
    password: &'a str,
    operation: &'a str,
}

#[derive(Deserialize)]
struct LoginResult {
    data: LoginResultData,
    success: bool,
}

#[derive(Deserialize)]
struct LoginResultData {
    _tid_: Option<String>,
}

fn login(client: &mut Client, host: &str, username: &str, password: &str) -> Result<String> {
    let url = format!("https://{}/data/login.json", host);
    let request_data = LoginRequest {
        username,
        password,
        operation: "write",
    };
    let response_data: LoginResult = client.post(url).json(&request_data).send()?.json()?;
    if response_data.success {
        Ok(response_data.data._tid_.unwrap())
    } else {
        bail!("Failed to login")
    }
}

#[derive(Deserialize)]
struct UploadCertResult {
    success: bool,
}

fn upload_cert(
    client: &mut Client,
    host: &str,
    tid: &str,
    method: &str,
    cert_data: Vec<u8>,
) -> Result<()> {
    let url = format!("https://{}/data/{}?usrLvl=3&_tid_={}", host, method, tid);
    let part = Part::bytes(cert_data)
        .file_name("cert.pem")
        .mime_str("application/x-x509-ca-cert")?;
    let form = Form::new().part("file", part);
    let result: UploadCertResult = client.post(url).multipart(form).send()?.json()?;
    if result.success {
        Ok(())
    } else {
        bail!("Failed to upload cert");
    }
}

fn main() -> Result<()> {
    let mut args = args().skip(1);
    let Some(host) = args.next() else { bail!("host is required") };
    let Some(username) = args.next() else { bail!("username is required") };
    let Some(password) = args.next() else { bail!("password is required") };
    let Some(cert_file) = args.next() else { bail!("cert_file is required") };
    let Some(key_file) = args.next() else { bail!("key_file is required") };

    let mut client = ClientBuilder::new()
        // This seems to be required since the router doesn't seem to
        // want to accept a full cert chain. So, that means that non-browser
        // clients will get upset about the incomplete chain. I'm not sure if
        // there is some way around that.
        .danger_accept_invalid_certs(true)
        .build()?;
    let tid = login(&mut client, &host, &username, &password)?;

    let mut cert_data = Vec::new();
    File::open(&cert_file)?.read_to_end(&mut cert_data)?;
    upload_cert(
        &mut client,
        &host,
        &tid,
        "httpsLoadCertificate.json",
        cert_data,
    )?;

    let mut key_data = Vec::new();
    File::open(&key_file)?.read_to_end(&mut key_data)?;
    upload_cert(&mut client, &host, &tid, "httpsLoadKey.json", key_data)?;

    println!("Cert updated");

    Ok(())
}
