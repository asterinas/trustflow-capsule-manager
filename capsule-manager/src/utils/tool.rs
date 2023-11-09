// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use base64::engine::general_purpose;
use base64::Engine as _;
use openssl::pkey::{PKey, Public};
use openssl::sha::Sha256;
use openssl::x509::X509;

use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use crate::{cm_assert, errno, return_errno};

pub fn sha256(buf: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(buf);
    hasher.finish()
}

pub fn sha256_with_base64_encode(buf: &[u8]) -> String {
    general_purpose::STANDARD.encode(sha256(buf))
}

pub fn get_cert_from_cert_chain(
    cert_chain: &Vec<Vec<u8>>,
    index: usize,
    format: &str,
) -> AuthResult<X509> {
    let cert = match format {
        "PEM" => openssl::x509::X509::from_pem(cert_chain.get(index).ok_or(errno!(
            ErrorCode::InvalidArgument,
            "cert chain index{} is empty",
            index
        ))?)?,
        "DER" => openssl::x509::X509::from_der(cert_chain.get(index).ok_or(errno!(
            ErrorCode::InvalidArgument,
            "cert chain index{} is empty",
            index
        ))?)?,
        _ => return_errno!(ErrorCode::InvalidArgument, "format {} not support", format),
    };
    Ok(cert)
}

pub fn get_public_key_from_cert_chain(
    cert_chain: &Vec<Vec<u8>>,
    index: usize,
    format: &str,
) -> AuthResult<PKey<Public>> {
    let cert = get_cert_from_cert_chain(cert_chain, index, format)?;
    Ok(cert.public_key()?)
}

pub fn verify_cert_chain(cert_chain: &Vec<Vec<u8>>, format: &str) -> AuthResult<()> {
    cm_assert!(!cert_chain.is_empty(), "cert chain is empty");

    for index in 0..(cert_chain.len() - 1) {
        let parent_pk = get_public_key_from_cert_chain(cert_chain, index + 1, format)?;
        let current_cert = get_cert_from_cert_chain(cert_chain, index, format)?;
        // verify certification signature
        cm_assert!(
            current_cert.verify(&parent_pk)?,
            "certification-{} verify signature failed",
            index
        );
    }
    Ok(())
}

pub fn vec_str_to_vec_u8(vec_str: &Vec<String>) -> Vec<Vec<u8>> {
    return vec_str.iter().map(|x| x.clone().into_bytes()).collect();
}

// generate party_id from cert
// RFC4648 BASE32(SHA256(DER(X.509 public key)))
pub fn gen_party_id(pk: &PKey<Public>) -> AuthResult<String> {
    Ok(base32::encode(
        base32::Alphabet::RFC4648 { padding: false },
        &sha256(&pk.public_key_to_der()?),
    ))
}

#[cfg(test)]
mod tests {
    use super::{get_cert_from_cert_chain, verify_cert_chain};
    use base64::engine::general_purpose;
    use base64::Engine;

    #[test]
    fn test_verify_cert_chain_der() {
        let cert0 = "MIIDkzCCAnugAwIBAgIUd1LFNjoWq+lwVxMueA2zgdb5+l4wDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzEwMTMwODIxMTRaFw0yODEwMTEwODIxMTRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwyD/Gek04NtdV696Rwa2hlWdTdXQlAquu6dxcFqdLPDsicuKfIEoDNEMhqKhw27rH3/r1u7zL2iqBjDCvHWyEFH+pEatilOiSwAmPA2gjGf8obsrztOdi3oGpDmMck8AGDtUMz8is2pG+gi+D40X2MT2hUd4EsjxAVizQqRdHTU3Qscq1fKveQqK9SEDZAcFXLvYYFpN40gIymNGLqSiO2MY7n8SDZTBvm6s5Srqdxmk1qH96iI1LQ1W0XQ9XR99MqhnZajzuO8SuB0LhFvOVqzKpM2oWWC/4WYgCBd4f17h9WMkT6ElwO+qlORXksAUi4oIwxB6UhUsgz2N3u4bHAgMBAAGjezB5MB8GA1UdIwQYMBaAFNYratn4oPKSSNZVSpXIfzjV3DG/MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgTwMB8GA1UdEQQYMBaCCWxvY2FsaG9zdIIJMTI3LjAuMC4xMB0GA1UdDgQWBBQOGk3ygjT9kj2k9UDMJJxl7fL9MzANBgkqhkiG9w0BAQsFAAOCAQEAvphkkc1J7NC+RY6xtW2bR5EjuV5xHll7sPaGVesOgVoKbbFnAmvej9ngrajhcKRPCz7wngPBUKZjZEI5tuBk7dQ6y1bx6HKUqAFcekahEznYUxtOZJoX7br6J66ZKnkgaduWzWlrx8KmwOdGiKpxuVo3iZJwDYkt2DPB+r8DHMwxlopm4+Tayg9QyfhPDbB/e8jg3dBDmdAyPoVsSEmbZDIocgnmz3XQCsx1RmXbNcd8HFZaX2OSEaG3DoQI30GgVaPeq1qRivm605/pLykw5m5ZzY3txrIE2EcFJVI37lh9xJD4FKNAJheHemLDiqwtjQCj3QJCumH+SHLmb/HWeQ==";
        let cert1 = "MIIDazCCAlOgAwIBAgIUFpdQY1bRpOs6eqYrlqBBdMcGzZAwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMzEwMTMwODIxMDNaFw0yODEwMTEwODIxMDNaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLhTtwZWZ4CyAGQNKnCCrU454OVu6/LEsafKTQdsTLNQWeINVGL0s/SWKib2brzN7Gyj+e6IBGwtr7RjLYHrYcwpSEQxcc9p1oks6Lzhi4pwhORp60WrOTpUfsjAugQpPu+/dj5a9onOfqGjf5fEzzLtt86wMX2YrWHMGakYICeaa/lPa1YIi5bmQXNAH7yH+jfylBkIfB589AWNm1HJxoFZhrFavUqXMgcal1GEy1rQwVu/BXFPswEsuq2esTjc7C3745SerFBWHYBaBJBCLEPLjd+M/TrcYZBidIB9WuEx6Y/2Ho/sjTz+ww8FIjkdcwPv5Pq8+VmXvHlRteLikTAgMBAAGjUzBRMB0GA1UdDgQWBBTWK2rZ+KDykkjWVUqVyH841dwxvzAfBgNVHSMEGDAWgBTWK2rZ+KDykkjWVUqVyH841dwxvzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA0oyIKEfM45rKMGbUD6X5pZCZyKajVGWjzIH+DazhLRRR/K6dRrxG4C5ijTtU7XXTuDfEF0JyLizdiL3nNd8LIDARL8+7pwawBSjF1rrQFO341ylskXLfTtOE8L21Ol3I/twIE8rpyUVPF/AfUYLnbAJDq0hSxxskhdqwKQGBcnsgQqITLRdJ+GV3LcOKs4Oi00O8Vl51CFA+tNwX+J3eGYH5ZAV4P5rHEuiEOezFikuq/sz+6zYRTWwYFHyz0PcggDNpEaCvCTw/kBJbvp6K+x3HBqiaIr51PO7yUC+OEUanXCwqcqQiG4hKh1YZ94iNIIcSAaWKT20kIbKpFpyQH";
        let cert_chain = vec![
            general_purpose::STANDARD.decode(cert0).unwrap(),
            general_purpose::STANDARD.decode(cert1).unwrap(),
        ];
        verify_cert_chain(&cert_chain, "DER").unwrap();
        let x5090 = get_cert_from_cert_chain(&cert_chain, 0, "DER").unwrap();
        let x5091 = get_cert_from_cert_chain(&cert_chain, 1, "DER").unwrap();

        assert_eq!(
            general_purpose::STANDARD.encode(&x5090.to_der().unwrap()),
            cert0
        );
        assert_eq!(
            general_purpose::STANDARD.encode(&x5091.to_der().unwrap()),
            cert1
        );
    }
}
