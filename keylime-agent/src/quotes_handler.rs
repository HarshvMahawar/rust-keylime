// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::common::JsonWrapper;
use std::collections::HashMap;
use keylime::tpm::testing::decode_quote_string;
use crate::crypto;
use crate::serialization::serialize_maybe_base64;
use crate::{tpm, Error as KeylimeError, QuoteData};
use actix_web::{http, web, HttpRequest, HttpResponse, Responder};
use base64::{engine::general_purpose, Engine as _};
use keylime::quote::{Integ, KeylimeQuote};

use keylime::tpm::{CMW, Evidence, EvidenceEntry};

use log::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{read, read_to_string},
    io::{Read, Seek},
};
use tss_esapi::structures::PcrSlot;

#[derive(Deserialize)]
pub struct Ident {
    nonce: String,
}

// This is a Quote request from the tenant, which does not check
// integrity measurement. It should return this data:
// { QuoteAIK(nonce, 16:H(NK_pub)), NK_pub }
async fn identity(
    req: HttpRequest,
    param: web::Query<Ident>,
    data: web::Data<QuoteData<'_>>,
) -> impl Responder {
    // nonce can only be in alphanumerical format
    if !param.nonce.chars().all(char::is_alphanumeric) {
        warn!("Get quote returning 400 response. Parameters should be strictly alphanumeric: {}", param.nonce);
        return HttpResponse::BadRequest().json(JsonWrapper::error(
            400,
            format!(
                "Parameters should be strictly alphanumeric: {}",
                param.nonce
            ),
        ));
    }

    if param.nonce.len() > tpm::MAX_NONCE_SIZE {
        warn!("Get quote returning 400 response. Nonce is too long (max size {}): {}",
              tpm::MAX_NONCE_SIZE,
              param.nonce.len()
        );
        return HttpResponse::BadRequest().json(JsonWrapper::error(
            400,
            format!(
                "Nonce is too long (max size {}): {}",
                tpm::MAX_NONCE_SIZE,
                param.nonce
            ),
        ));
    }

    debug!("Calling Identity Quote with nonce: {}", param.nonce);

    // must unwrap here due to lock mechanism
    // https://github.com/rust-lang-nursery/failure/issues/192
    let mut context = data.tpmcontext.lock().unwrap(); //#[allow_ci]

    let tpm_quote = match context.quote(
        param.nonce.as_bytes(),
        0,
        &data.pub_key,
        data.ak_handle,
        data.hash_alg,
        data.sign_alg,
    ) {
        Ok(quote) => quote,
        Err(e) => {
            debug!("Unable to retrieve quote: {:?}", e);
            return HttpResponse::InternalServerError().json(
                JsonWrapper::error(
                    500,
                    "Unable to retrieve quote".to_string(),
                ),
            );
        }
    };

    let mut quote = KeylimeQuote {
        quote: tpm_quote,
        hash_alg: data.hash_alg.to_string(),
        enc_alg: data.enc_alg.to_string(),
        sign_alg: data.sign_alg.to_string(),
        ..Default::default()
    };

    match crypto::pkey_pub_to_pem(&data.pub_key) {
        Ok(pubkey) => quote.pubkey = Some(pubkey),
        Err(e) => {
            debug!("Unable to retrieve public key for quote: {:?}", e);
            return HttpResponse::InternalServerError().json(
                JsonWrapper::error(
                    500,
                    "Unable to retrieve quote".to_string(),
                ),
            );
        }
    }

    let response = JsonWrapper::success(quote);
    info!("GET identity quote returning 200 response");
    HttpResponse::Ok().json(response)
}

pub fn extract_api_version(req: &HttpRequest) -> String {
    // Get path like "/v3/quotes/integrity"
    let path = req.path();

    for segment in path.split('/') {
        if segment.starts_with('v') {
            return segment.to_string();
        }
    }

    // default fallback to v2.2
    "v2.2".to_string()
}

use tss_esapi::traits::Marshall;

use base64::Engine;

/// parse the quote string and returns TPMS_ATTEST, TPMT_SIGNATURE, PCRs as byte arrays
pub fn parse_quote_fields(quote_str: &str) -> HashMap<&'static str, Vec<u8>> {
    let mut result = HashMap::new();

    let cleaned = quote_str.strip_prefix('r').unwrap_or(quote_str);

    let parts: Vec<&str> = cleaned.splitn(3, ':').collect();
    if parts.len() != 3 {
        return result;
    }

    _ = result.insert(
        "TPMS_ATTEST",
        general_purpose::STANDARD.decode(parts[0]).unwrap_or_default(),
    );
    _ = result.insert(
        "TPMT_SIGNATURE",
        general_purpose::STANDARD.decode(parts[1]).unwrap_or_default(),
    );
    _ = result.insert(
        "PCRs",
        general_purpose::STANDARD.decode(parts[2]).unwrap_or_default(),
    );

    result
}

// This is a Quote request from the cloud verifier, which will check
// integrity measurement. The PCRs included in the Quote will be specified
// by the mask. It should return this data:
// { QuoteAIK(nonce, 16:H(NK_pub), xi:yi), NK_pub}
// where xi:yi are additional PCRs to be included in the quote.
async fn integrity(
    req: HttpRequest,
    param: web::Query<Integ>,
    data: web::Data<QuoteData<'_>>,
) -> impl Responder {

    let api_version = extract_api_version(&req);

    // nonce, mask can only be in alphanumerical format
    if !param.nonce.chars().all(char::is_alphanumeric) {
        warn!("Get quote returning 400 response. Parameters should be strictly alphanumeric: {}", param.nonce);
        return HttpResponse::BadRequest().json(JsonWrapper::error(
            400,
            format!("nonce should be strictly alphanumeric: {}", param.nonce),
        ));
    }

    if !param.mask.chars().all(char::is_alphanumeric) {
        warn!("Get quote returning 400 response. Parameters should be strictly alphanumeric: {}", param.mask);
        return HttpResponse::BadRequest().json(JsonWrapper::error(
            400,
            format!("mask should be strictly alphanumeric: {}", param.mask),
        ));
    }

    let mask =
        match u32::from_str_radix(param.mask.trim_start_matches("0x"), 16) {
            Ok(mask) => mask,
            Err(e) => {
                return HttpResponse::BadRequest().json(JsonWrapper::error(
                    400,
                    format!(
                        "mask should be a hex encoded 32-bit integer: {}",
                        param.mask
                    ),
                ));
            }
        };

    if param.nonce.len() > tpm::MAX_NONCE_SIZE {
        warn!("Get quote returning 400 response. Nonce is too long (max size {}): {}",
              tpm::MAX_NONCE_SIZE,
              param.nonce.len()
        );
        return HttpResponse::BadRequest().json(JsonWrapper::error(
            400,
            format!(
                "Nonce is too long (max size: {}): {}",
                tpm::MAX_NONCE_SIZE,
                param.nonce.len()
            ),
        ));
    }

    // If partial="0", include the public key in the quote
    let pubkey = match &param.partial[..] {
        "0" => {
            let pubkey = match crypto::pkey_pub_to_pem(&data.pub_key) {
                Ok(pubkey) => pubkey,
                Err(e) => {
                    debug!("Unable to retrieve public key: {:?}", e);
                    return HttpResponse::InternalServerError().json(
                        JsonWrapper::error(
                            500,
                            "Unable to retrieve public key".to_string(),
                        ),
                    );
                }
            };
            Some(pubkey)
        }
        "1" => None,
        _ => {
            warn!("Get quote returning 400 response. uri must contain key 'partial' and value '0' or '1'");
            return HttpResponse::BadRequest().json(JsonWrapper::error(
                400,
                "uri must contain key 'partial' and value '0' or '1'"
                    .to_string(),
            ));
        }
    };

    debug!(
        "Calling Integrity Quote with nonce: {}, mask: {}",
        param.nonce, param.mask
    );

    // If an index was provided, the request is for the entries starting from the given index
    // (iterative attestation). Otherwise the request is for the whole list.
    let nth_entry = match &param.ima_ml_entry {
        None => 0,
        Some(idx) => idx.parse::<u64>().unwrap_or(0),
    };

    // must unwrap here due to lock mechanism
    // https://github.com/rust-lang-nursery/failure/issues/192
    let mut context = data.tpmcontext.lock().unwrap(); //#[allow_ci]

    // Generate the ID quote.
    let tpm_quote = match context.quote(
        param.nonce.as_bytes(),
        mask,
        &data.pub_key,
        data.ak_handle,
        data.hash_alg,
        data.sign_alg,
    ) {
        Ok(tpm_quote) => tpm_quote,
        Err(e) => {
            debug!("Unable to retrieve quote: {:?}", e);
            return HttpResponse::InternalServerError().json(
                JsonWrapper::error(
                    500,
                    "Unable to retrieve quote".to_string(),
                ),
            );
        }
    };

    let id_quote = KeylimeQuote {
        quote: tpm_quote,
        hash_alg: data.hash_alg.to_string(),
        enc_alg: data.enc_alg.to_string(),
        sign_alg: data.sign_alg.to_string(),
        ..Default::default()
    };

    // If PCR 0 is included in the mask, obtain the measured boot
    let mut mb_measurement_list = None;
    match tpm::check_mask(mask, &PcrSlot::Slot0) {
        Ok(true) => {
            if let Some(measuredboot_ml_file) = &data.measuredboot_ml_file {
                let mut ml = Vec::<u8>::new();
                let mut f = measuredboot_ml_file.lock().unwrap(); //#[allow_ci]
                if let Err(e) = f.rewind() {
                    debug!("Failed to rewind measured boot file: {}", e);
                    return HttpResponse::InternalServerError().json(
                        JsonWrapper::error(
                            500,
                            "Unable to retrieve quote".to_string(),
                        ),
                    );
                }
                mb_measurement_list = match f.read_to_end(&mut ml) {
                    Ok(_) => Some(general_purpose::STANDARD.encode(ml)),
                    Err(e) => {
                        warn!("Could not read TPM2 event log: {}", e);
                        None
                    }
                };
            }
        }
        Err(e) => {
            debug!("Unable to check PCR mask: {:?}", e);
            return HttpResponse::InternalServerError().json(
                JsonWrapper::error(
                    500,
                    "Unable to retrieve quote".to_string(),
                ),
            );
        }
        _ => (),
    }

    // Generate the measurement list
    let (ima_measurement_list, ima_measurement_list_entry, num_entries) =
        if let Some(ima_file) = &data.ima_ml_file {
            let mut ima_ml = data.ima_ml.lock().unwrap(); //#[allow_ci]
            match ima_ml.read(
                &mut ima_file.lock().unwrap(), //#[allow_ci]
                nth_entry,
            ) {
                Ok(result) => {
                    (Some(result.0), Some(result.1), Some(result.2))
                }
                Err(e) => {
                    debug!("Unable to read measurement list: {:?}", e);
                    return HttpResponse::InternalServerError().json(
                        JsonWrapper::error(
                            500,
                            "Unable to retrieve quote".to_string(),
                        ),
                    );
                }
            }
        } else {
            (None, None, None)
        };

    if api_version == "v3" {
        let parsed_quote = parse_quote_fields(&id_quote.quote);
        let event_log = build_event_log(
            ima_measurement_list.as_deref().unwrap_or(""),
            mb_measurement_list.as_deref(),
        );
        let metadata = get_keylime_metadata(
            pubkey.clone(),
            Some("123".to_string()), // where to get boottime?
            &id_quote.hash_alg,
            &id_quote.sign_alg,
        );
        let cmw = build_cmw(
            &parsed_quote["TPMS_ATTEST"],
            &parsed_quote["TPMT_SIGNATURE"],
            &parsed_quote["PCRs"],
            &event_log,
            &metadata,
        );

        return HttpResponse::Ok().json(cmw);
    }

    // Generate the final quote based on the ID quote
    let quote = KeylimeQuote {
        pubkey,
        ima_measurement_list,
        mb_measurement_list,
        ima_measurement_list_entry,
        ..id_quote
    };

    let response = JsonWrapper::success(quote);
    info!("GET integrity quote returning 200 response");
    HttpResponse::Ok().json(response)
}

/// Handles the default case for the /quotes scope
async fn quotes_default(req: HttpRequest) -> impl Responder {
    let error;
    let response;
    let message;

    match req.head().method {
        http::Method::GET => {
            error = 400;
            message = "URI not supported, only /identity and /integrity are supported for GET in /quotes/ interface";
            response = HttpResponse::BadRequest()
                .json(JsonWrapper::error(error, message));
        }
        _ => {
            error = 405;
            message = "Method is not supported in /quotes/ interface";
            response = HttpResponse::MethodNotAllowed()
                .insert_header(http::header::Allow(vec![http::Method::GET]))
                .json(JsonWrapper::error(error, message));
        }
    };

    warn!(
        "{} returning {} response. {}",
        req.head().method,
        error,
        message
    );

    response
}

/// Configure the endpoints for the /quotes scope
pub(crate) fn configure_quotes_endpoints(cfg: &mut web::ServiceConfig) {
    _ = cfg
        .service(web::resource("/identity").route(web::get().to(identity)))
        .service(web::resource("/integrity").route(web::get().to(integrity)))
        .default_service(web::to(quotes_default));
}

#[cfg(feature = "testing")]
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use keylime::{crypto::testing::pkey_pub_from_pem, tpm};
    use serde_json::{json, Value};

    #[actix_rt::test]
    async fn test_identity() {
        let (fixture, mutex) = QuoteData::fixture().await.unwrap(); //#[allow_ci]
        let quotedata = web::Data::new(fixture);
        let mut app = test::init_service(
            App::new()
                .app_data(quotedata.clone())
                .route("/vX.Y/quotes/identity", web::get().to(identity)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/vX.Y/quotes/identity?nonce=1234567890ABCDEFHIJ")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeQuote> =
            test::read_body_json(resp).await;
        assert_eq!(result.results.hash_alg.as_str(), "sha256");
        assert_eq!(result.results.enc_alg.as_str(), "rsa");
        assert_eq!(result.results.sign_alg.as_str(), "rsassa");
        assert!(
            pkey_pub_from_pem(&result.results.pubkey.unwrap()) //#[allow_ci]
                .unwrap() //#[allow_ci]
                .public_eq(&quotedata.pub_key)
        );
        assert!(result.results.quote.starts_with('r'));

        let mut context = quotedata.tpmcontext.lock().unwrap(); //#[allow_ci]
        tpm::testing::check_quote(
            &mut context,
            quotedata.ak_handle,
            &result.results.quote,
            b"1234567890ABCDEFHIJ",
        )
        .expect("unable to verify quote");

        // Explicitly drop QuoteData to cleanup keys
        drop(context);
        drop(quotedata);
    }

    #[actix_rt::test]
    async fn test_integrity_pre() {
        let (fixture, mutex) = QuoteData::fixture().await.unwrap(); //#[allow_ci]
        let quotedata = web::Data::new(fixture);
        let mut app = test::init_service(
            App::new()
                .app_data(quotedata.clone())
                .route("vX.Y/quotes/integrity", web::get().to(integrity)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(
                "/vX.Y/quotes/integrity?nonce=1234567890ABCDEFHIJ&mask=0x408000&partial=0",
            )
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeQuote> =
            test::read_body_json(resp).await;
        assert_eq!(result.results.hash_alg.as_str(), "sha256");
        assert_eq!(result.results.enc_alg.as_str(), "rsa");
        assert_eq!(result.results.sign_alg.as_str(), "rsassa");
        assert!(
            pkey_pub_from_pem(&result.results.pubkey.unwrap()) //#[allow_ci]
                .unwrap() //#[allow_ci]
                .public_eq(&quotedata.pub_key)
        );

        if let Some(ima_mutex) = &quotedata.ima_ml_file {
            let mut ima_ml_file = ima_mutex.lock().unwrap(); //#[allow_ci]
            ima_ml_file.rewind().unwrap(); //#[allow_ci]
            let mut ima_ml = String::new();
            match ima_ml_file.read_to_string(&mut ima_ml) {
                Ok(_) => {
                    assert_eq!(
                        result.results.ima_measurement_list.unwrap().as_str(), //#[allow_ci]
                        ima_ml
                    );
                    assert!(result.results.quote.starts_with('r'));

                    let mut context = quotedata.tpmcontext.lock().unwrap(); //#[allow_ci]
                    tpm::testing::check_quote(
                        &mut context,
                        quotedata.ak_handle,
                        &result.results.quote,
                        b"1234567890ABCDEFHIJ",
                    )
                    .expect("unable to verify quote");
                }
                Err(e) => panic!("Could not read IMA file: {e}"), //#[allow_ci]
            }
        } else {
            panic!("IMA file was None"); //#[allow_ci]
        }

        // Explicitly drop QuoteData to cleanup keys
        drop(quotedata);
    }

    #[actix_rt::test]
    async fn test_integrity_post() {
        let (fixture, mutex) = QuoteData::fixture().await.unwrap(); //#[allow_ci]
        let quotedata = web::Data::new(fixture);
        let mut app = test::init_service(
            App::new()
                .app_data(quotedata.clone())
                .route("/vX.Y/quotes/integrity", web::get().to(integrity)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(
                "/vX.Y/quotes/integrity?nonce=1234567890ABCDEFHIJ&mask=0x408000&partial=1",
            )
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeQuote> =
            test::read_body_json(resp).await;
        assert_eq!(result.results.hash_alg.as_str(), "sha256");
        assert_eq!(result.results.enc_alg.as_str(), "rsa");
        assert_eq!(result.results.sign_alg.as_str(), "rsassa");

        if let Some(ima_mutex) = &quotedata.ima_ml_file {
            let mut ima_ml_file = ima_mutex.lock().unwrap(); //#[allow_ci]
            ima_ml_file.rewind().unwrap(); //#[allow_ci]
            let mut ima_ml = String::new();
            match ima_ml_file.read_to_string(&mut ima_ml) {
                Ok(_) => {
                    assert_eq!(
                        result.results.ima_measurement_list.unwrap().as_str(), //#[allow_ci]
                        ima_ml
                    );
                    assert!(result.results.quote.starts_with('r'));
                }
                Err(e) => panic!("Could not read IMA file: {e}"), //#[allow_ci]
            }
        } else {
            panic!("IMA file was None"); //#[allow_ci]
        }

        let mut context = quotedata.tpmcontext.lock().unwrap(); //#[allow_ci]
        tpm::testing::check_quote(
            &mut context,
            quotedata.ak_handle,
            &result.results.quote,
            b"1234567890ABCDEFHIJ",
        )
        .expect("unable to verify quote");

        // Explicitly drop QuoteData to cleanup keys
        drop(context);
        drop(quotedata);
    }

    #[actix_rt::test]
    async fn test_missing_ima_file() {
        let (mut fixture, mutex) = QuoteData::fixture().await.unwrap(); //#[allow_ci]

        // Remove the IMA log file from the context
        fixture.ima_ml_file = None;
        let quotedata = web::Data::new(fixture);
        let mut app = test::init_service(
            App::new()
                .app_data(quotedata.clone())
                .route("/vX.Y/quotes/integrity", web::get().to(integrity)),
        )
        .await;

        let req = test::TestRequest::get()
            .uri(
                "/vX.Y/quotes/integrity?nonce=1234567890ABCDEFHIJ&mask=0x408000&partial=0",
            )
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let result: JsonWrapper<KeylimeQuote> =
            test::read_body_json(resp).await;
        assert!(result.results.ima_measurement_list.is_none());
        assert!(result.results.ima_measurement_list_entry.is_none());

        // Explicitly drop QuoteData to cleanup keys
        drop(quotedata);
    }

    #[actix_rt::test]
    async fn test_keys_default() {
        let mut app = test::init_service(
            App::new().service(web::resource("/").to(quotes_default)),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let result: JsonWrapper<Value> = test::read_body_json(resp).await;

        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 400);

        let req = test::TestRequest::delete().uri("/").to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());

        let headers = resp.headers();

        assert!(headers.contains_key("allow"));
        assert_eq!(headers.get("allow").unwrap().to_str().unwrap(), "GET"); //#[allow_ci]

        let result: JsonWrapper<Value> = test::read_body_json(resp).await;

        assert_eq!(result.results, json!({}));
        assert_eq!(result.code, 405);
    }
}

// CMW functions

fn build_cmw(
    tpms_attest: &[u8],
    tpmt_signature: &[u8],
    pcr_values: &[u8],
    event_log: &Value,
    keylime_metadata: &Value,
) -> CMW {
    CMW {
        cmwc_type: "tag:keylime.org,2025:tpm2-agent".to_string(),
        evidence: Evidence {
            tpms_attest: EvidenceEntry(
                "application/vnd.keylime.tpm2.tpms_attest".to_string(),
                general_purpose::URL_SAFE_NO_PAD.encode(tpms_attest),
            ),
            tpmt_signature: EvidenceEntry(
                "application/vnd.keylime.tpm2.tpmt_signature".to_string(),
                general_purpose::URL_SAFE_NO_PAD.encode(tpmt_signature),
            ),
            pcr_values: EvidenceEntry(
                "application/vnd.keylime.tpm2.pcr_values".to_string(),
                general_purpose::URL_SAFE_NO_PAD.encode(pcr_values),
            ),
            event_log: EvidenceEntry(
                "application/vnd.keylime.cel".to_string(),
                general_purpose::URL_SAFE_NO_PAD.encode(
                    serde_json::to_string(event_log).unwrap().as_bytes(),
                ),
            ),
            keylime_metadata: EvidenceEntry(
                "application/vnd.keylime.tpm2.metadata".to_string(),
                general_purpose::URL_SAFE_NO_PAD.encode(
                    serde_json::to_string(keylime_metadata).unwrap().as_bytes(),
                ),
            ),
        },
    }
}

use serde_json::{json, Value};

fn build_event_log(ima_list_str: &str, mb_list_b64: Option<&str>) -> Value {
    let mut cel = Vec::new();
    let mut recnum = 0;

    // --- IMA measurement list (PCR 10) ---
    for line in ima_list_str.lines() {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let pcr_index: u32 = parts[0].parse().unwrap_or(10); // fallback to PCR 10
        let template_type = parts[2];
        let template_hash = parts[3];
        let path = parts[4];

        if let Some((hash_alg, hash_val)) = template_hash.split_once(':') {
            if let Ok(digest_bytes) = hex::decode(hash_val) {
                let entry = json!({
                    "recnum": recnum,
                    "pcr": pcr_index,
                    "digests": [{
                        "hashAlg": hash_alg.to_lowercase(),
                        "digest": general_purpose::URL_SAFE_NO_PAD.encode(&digest_bytes)
                    }],
                    "content_type": "ima_template",
                    "content": {
                        "template_name": template_type,
                        "template_data": general_purpose::URL_SAFE_NO_PAD.encode(format!("{} {}", template_hash, path).as_bytes())
                    }
                });
                cel.push(entry);
                recnum += 1;
            }
        }
    }

    // --- Measured Boot Log (PCR 0) ---
    if let Some(mb64) = mb_list_b64 {
        if let Ok(decoded) = general_purpose::STANDARD.decode(mb64) {
            let sha1_digest = general_purpose::URL_SAFE_NO_PAD.encode(&decoded[..20]);
            let full_encoded = general_purpose::URL_SAFE_NO_PAD.encode(&decoded);
            let entry = json!({
                "recnum": recnum,
                "pcr": 0,
                "digests": [{
                    "hashAlg": "sha1",
                    "digest": sha1_digest
                }],
                "content_type": "pcclient_std",
                "content": full_encoded
            });
            cel.push(entry);
        }
    }

    Value::Array(cel)
}

fn get_keylime_metadata(
    pubkey: Option<String>,
    boottime: Option<String>,
    hash_alg: &str,
    sign_alg: &str,
) -> Value {
    json!({
        "boottime": boottime,
        "pubkey": pubkey,
        "hash_alg": hash_alg,
        "sign_alg": sign_alg
    })
}