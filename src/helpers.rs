use reqwest::header::HeaderValue;
use std::time::Duration;
use thiserror::Error;

/// Simple helper function to check a banner url
pub async fn check_banner_img(client: &reqwest::Client, url: &str) -> Result<(), BannerCheckError> {
    if url.is_empty() {
        return Ok(());
    }

    let req = client.get(url)
    .timeout(Duration::from_secs(10))
    .send()
    .await
    .map_err(BannerCheckError::BadURL)?;

    let status = req.status();

    if !status.is_success() {
        return Err(BannerCheckError::StatusError(status.to_string()));
    }

    let default = &HeaderValue::from_str("").unwrap();
    let content_type = req.headers().get("Content-Type").unwrap_or(default).to_str().unwrap();

    if content_type.split('/').next().unwrap() != "image" {
        return Err(BannerCheckError::BadContentType(content_type.to_string()));
    }

    Ok(())
}

#[derive(Error, Debug)]
pub enum BannerCheckError {
    #[error("Bad banner url: {0}")]
    BadURL(#[from] reqwest::Error),
    #[error("Got status code: {0} when requesting this banner")]
    StatusError(String),
    #[error("Got invalid content type: {0} when requesting this banner")]
    BadContentType(String),
}