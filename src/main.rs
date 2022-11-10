use anyhow::{bail, Result};
use clap::Parser;
use reqwest::blocking::multipart::{Form, Part};
use reqwest::blocking::Client;
use reqwest::blocking::ClientBuilder;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

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

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    host: String,
    username: String,
    password: String,
    cert_file: PathBuf,
    key_file: PathBuf,
    #[arg(long, default_value_t = false)]
    insecure: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut client = ClientBuilder::new()
        .danger_accept_invalid_certs(if args.insecure { true } else { false })
        .build()?;
    let tid = login(&mut client, &args.host, &args.username, &args.password)?;

    let mut cert_data = Vec::new();
    File::open(&args.cert_file)?.read_to_end(&mut cert_data)?;
    upload_cert(
        &mut client,
        &args.host,
        &tid,
        "httpsLoadCertificate.json",
        cert_data,
    )?;

    let mut key_data = Vec::new();
    File::open(&args.key_file)?.read_to_end(&mut key_data)?;
    upload_cert(&mut client, &args.host, &tid, "httpsLoadKey.json", key_data)?;

    println!("Cert updated");

    Ok(())
}
