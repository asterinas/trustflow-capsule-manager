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
    fn test_verify_cert_chain_pem() {
        let cert0 = "-----BEGIN CERTIFICATE-----\nMIIJ6DCCCNCgAwIBAgIMVeasrtH4pDD5qTjFMA0GCSqGSIb3DQEBCwUAMFAxCzAJ\nBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1H\nbG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODAeFw0yMzA3MDYwMTUxMDZaFw0y\nNDA4MDYwMTUxMDVaMIGAMQswCQYDVQQGEwJDTjEQMA4GA1UECBMHYmVpamluZzEQ\nMA4GA1UEBxMHYmVpamluZzE5MDcGA1UEChMwQmVpamluZyBCYWlkdSBOZXRjb20g\nU2NpZW5jZSBUZWNobm9sb2d5IENvLiwgTHRkMRIwEAYDVQQDEwliYWlkdS5jb20w\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7BLuEdlgHtFqIVOBqVrzl\n1I0+Hrko4NcBjzgrQbJZffCsJ7QmJBQ4/kzqO0lR9+lbQPc/psjaDwJuJYtHkbgu\nngAhGR0YAPzeBP0meTld8pC8gJ2ofLKRiYnYQC/l0qfzXm1IK8UfCrHgjox2/7zR\nZwrSSdYJ7iYDAvPMzeqK1TGoLY8D/V785DrGiWeZTM6YbfqEDQ5Ti+ZjUsWbSqmr\noyI1mQ3uGf+bLfWkd/LsEID0q4K50X42Hw6fmxmg9cNX3Yi7zuGQnD9Lut06qUGz\n3YZNwsK36P83E8AEiUNEOBHmo5b3CSIhLyxODn7l2Fy7AERbr97ks7DwPLY4RUld\nAgMBAAGjggaPMIIGizAOBgNVHQ8BAf8EBAMCBaAwgY4GCCsGAQUFBwEBBIGBMH8w\nRAYIKwYBBQUHMAKGOGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0\nL2dzcnNhb3Zzc2xjYTIwMTguY3J0MDcGCCsGAQUFBzABhitodHRwOi8vb2NzcC5n\nbG9iYWxzaWduLmNvbS9nc3JzYW92c3NsY2EyMDE4MFYGA1UdIARPME0wQQYJKwYB\nBAGgMgEUMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29t\nL3JlcG9zaXRvcnkvMAgGBmeBDAECAjAJBgNVHRMEAjAAMD8GA1UdHwQ4MDYwNKAy\noDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nyc2FvdnNzbGNhMjAxOC5j\ncmwwggNhBgNVHREEggNYMIIDVIIJYmFpZHUuY29tggxiYWlmdWJhby5jb22CDHd3\ndy5iYWlkdS5jboIQd3d3LmJhaWR1LmNvbS5jboIPbWN0LnkubnVvbWkuY29tggth\ncG9sbG8uYXV0b4IGZHd6LmNuggsqLmJhaWR1LmNvbYIOKi5iYWlmdWJhby5jb22C\nESouYmFpZHVzdGF0aWMuY29tgg4qLmJkc3RhdGljLmNvbYILKi5iZGltZy5jb22C\nDCouaGFvMTIzLmNvbYILKi5udW9taS5jb22CDSouY2h1YW5rZS5jb22CDSoudHJ1\nc3Rnby5jb22CDyouYmNlLmJhaWR1LmNvbYIQKi5leXVuLmJhaWR1LmNvbYIPKi5t\nYXAuYmFpZHUuY29tgg8qLm1iZC5iYWlkdS5jb22CESouZmFueWkuYmFpZHUuY29t\ngg4qLmJhaWR1YmNlLmNvbYIMKi5taXBjZG4uY29tghAqLm5ld3MuYmFpZHUuY29t\ngg4qLmJhaWR1cGNzLmNvbYIMKi5haXBhZ2UuY29tggsqLmFpcGFnZS5jboINKi5i\nY2Vob3N0LmNvbYIQKi5zYWZlLmJhaWR1LmNvbYIOKi5pbS5iYWlkdS5jb22CEiou\nYmFpZHVjb250ZW50LmNvbYILKi5kbG5lbC5jb22CCyouZGxuZWwub3JnghIqLmR1\nZXJvcy5iYWlkdS5jb22CDiouc3UuYmFpZHUuY29tgggqLjkxLmNvbYISKi5oYW8x\nMjMuYmFpZHUuY29tgg0qLmFwb2xsby5hdXRvghIqLnh1ZXNodS5iYWlkdS5jb22C\nESouYmouYmFpZHViY2UuY29tghEqLmd6LmJhaWR1YmNlLmNvbYIOKi5zbWFydGFw\ncHMuY26CDSouYmR0anJjdi5jb22CDCouaGFvMjIyLmNvbYIMKi5oYW9rYW4uY29t\ngg8qLnBhZS5iYWlkdS5jb22CESoudmQuYmRzdGF0aWMuY29tghEqLmNsb3VkLmJh\naWR1LmNvbYISY2xpY2suaG0uYmFpZHUuY29tghBsb2cuaG0uYmFpZHUuY29tghBj\nbS5wb3MuYmFpZHUuY29tghB3bi5wb3MuYmFpZHUuY29tghR1cGRhdGUucGFuLmJh\naWR1LmNvbTAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHwYDVR0jBBgw\nFoAU+O9/8s14Z6jeb48kjYjxhwMCs+swHQYDVR0OBBYEFO1zq/kgvnoZn1kfsp/y\nPy8/kYQSMIIBfgYKKwYBBAHWeQIEAgSCAW4EggFqAWgAdgBIsONr2qZHNA/lagL6\nnTDrHFIBy1bdLIHZu7+rOdiEcwAAAYko5XABAAAEAwBHMEUCIQDtGvRfSswr/1ff\n5bjL+SRct34Ue6PaRsDYvGhpiYejgwIgX/aCg9Og5EZbVLo+ZsrU9s3IJusYzZYj\nASJszEzwZ1oAdwDuzdBk1dsazsVct520zROiModGfLzs3sNRSFlGcR+1mwAAAYko\n5XAdAAAEAwBIMEYCIQC9HcMYKn54HivSbhH0wuWtwTaHYtuIvJD8IhPF+zJ9/gIh\nAICMnoiGocc6FGIMIYmMd7p7JJSXMZCpFXSibCwzg1ItAHUA2ra/az+1tiKfm8K7\nXGvocJFxbLtRhIU0vaQ9MEjX+6sAAAGJKOVtVwAABAMARjBEAiBUbWpp6uCjWPkX\n1a3kdzajezONw5Uwdn7l+xypjE6bdwIgG2GK8pH+5UqZTTKxNyqCRoiJDX7rAXzx\nO22aIRkkBcAwDQYJKoZIhvcNAQELBQADggEBABlaZ1BDsax6k6hoGHKLQH6mdd6s\nIfzJQRYgS/OMC7lHRa74XXn2QzUmAZjwuYY+KQHx37Byta540t9htnhnisl3mt7g\n5EEvnB7lO3yXP0IvreNJf50rAoiQaSUDARS5tcsPWT0tlz0C1VGQaQyBECLaxlHv\nSAzST95h8mqHFaVtcY43AqKFDx4ZdaOALmoaogKML+y9PYEDP4rAoOa0DghXywAc\nircbjzhxmo3AcQw/vNS+Vp33GMGqvuTfGobiYm8jhjBUeC1HH7StBSlzJJgUoBnA\nAv2QkE5iXOhNMYnD6Iuec1k7mJHKR6UFW8Uej4U5Ds61JgqATp8IShFJE2M=\n-----END CERTIFICATE-----\n";
        let cert1 = "-----BEGIN CERTIFICATE-----\nMIIETjCCAzagAwIBAgINAe5fIh38YjvUMzqFVzANBgkqhkiG9w0BAQsFADBMMSAw\nHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFs\nU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xODExMjEwMDAwMDBaFw0yODEx\nMjEwMDAwMDBaMFAxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52\nLXNhMSYwJAYDVQQDEx1HbG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODCCASIw\nDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdaydUMGCEAI9WXD+uu3Vxoa2uP\nUGATeoHLl+6OimGUSyZ59gSnKvuk2la77qCk8HuKf1UfR5NhDW5xUTolJAgvjOH3\nidaSz6+zpz8w7bXfIa7+9UQX/dhj2S/TgVprX9NHsKzyqzskeU8fxy7quRU6fBhM\nabO1IFkJXinDY+YuRluqlJBJDrnw9UqhCS98NE3QvADFBlV5Bs6i0BDxSEPouVq1\nlVW9MdIbPYa+oewNEtssmSStR8JvA+Z6cLVwzM0nLKWMjsIYPJLJLnNvBhBWk0Cq\no8VS++XFBdZpaFwGue5RieGKDkFNm5KQConpFmvv73W+eka440eKHRwup08CAwEA\nAaOCASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB0G\nA1UdDgQWBBT473/yzXhnqN5vjySNiPGHAwKz6zAfBgNVHSMEGDAWgBSP8Et/qC5F\nJK5NUPpjmove4t0bvDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6\nLy9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjMwNgYDVR0fBC8wLTAroCmgJ4Yl\naHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+\nMDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j\nb20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAJmQyC1fQorUC2bbmANz\nEdSIhlIoU4r7rd/9c446ZwTbw1MUcBQJfMPg+NccmBqixD7b6QDjynCy8SIwIVbb\n0615XoFYC20UgDX1b10d65pHBf9ZjQCxQNqQmJYaumxtf4z1s4DfjGRzNpZ5eWl0\n6r/4ngGPoJVpjemEuunl1Ig423g7mNA2eymw0lIYkN5SQwCuaifIFJ6GlazhgDEw\nfpolu4usBCOmmQDo8dIm7A9+O4orkjgTHY+GzYZSR+Y0fFukAj6KYXwidlNalFMz\nhriSqHKvoflShx8xpfywgVcvzfTO3PYkz6fiNJBonf6q8amaEsybwMbDqKWwIX7e\nSPY=\n-----END CERTIFICATE-----\n";
        let cert2 = "-----BEGIN CERTIFICATE-----\nMIIETjCCAzagAwIBAgINAe5fFp3/lzUrZGXWajANBgkqhkiG9w0BAQsFADBXMQsw\nCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UECxMH\nUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTE4MDkxOTAw\nMDAwMFoXDTI4MDEyODEyMDAwMFowTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290\nIENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNp\nZ24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDMJXaQeQZ4Ihb1wIO2\nhMoonv0FdhHFrYhy/EYCQ8eyip0EXyTLLkvhYIJG4VKrDIFHcGzdZNHr9SyjD4I9\nDCuul9e2FIYQebs7E4B3jAjhSdJqYi8fXvqWaN+JJ5U4nwbXPsnLJlkNc96wyOkm\nDoMVxu9bi9IEYMpJpij2aTv2y8gokeWdimFXN6x0FNx04Druci8unPvQu7/1PQDh\nBjPogiuuU6Y6FnOM3UEOIDrAtKeh6bJPkC4yYOlXy7kEkmho5TgmYHWyn3f/kRTv\nriBJ/K1AFUjRAjFhGV64l++td7dkmnq/X8ET75ti+w1s4FRpFqkD2m7pg5NxdsZp\nhYIXAgMBAAGjggEiMIIBHjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB\n/zAdBgNVHQ4EFgQUj/BLf6guRSSuTVD6Y5qL3uLdG7wwHwYDVR0jBBgwFoAUYHtm\nGkUNl8qJUC99BM00qP/8/UswPQYIKwYBBQUHAQEEMTAvMC0GCCsGAQUFBzABhiFo\ndHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9yb290cjEwMwYDVR0fBCwwKjAooCag\nJIYiaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LmNybDBHBgNVHSAEQDA+\nMDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5j\nb20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBACNw6c/ivvVZrpRCb8RD\nM6rNPzq5ZBfyYgZLSPFAiAYXof6r0V88xjPy847dHx0+zBpgmYILrMf8fpqHKqV9\nD6ZX7qw7aoXW3r1AY/itpsiIsBL89kHfDwmXHjjqU5++BfQ+6tOfUBJ2vgmLwgtI\nfR4uUfaNU9OrH0Abio7tfftPeVZwXwzTjhuzp3ANNyuXlava4BJrHEDOxcd+7cJi\nWOx37XMiwor1hkOIreoTbv3Y/kIvuX1erRjvlJDKPSerJpSZdcfL03v3ykzTr1Eh\nkluEfSufFT90y1HonoMOFm8b50bOI7355KKL0jlrqnkckSziYSQtjipIcJDEHsXo\n4HA=\n-----END CERTIFICATE-----\n";
        let cert_chain = vec![
            cert0.as_bytes().to_vec(),
            cert1.as_bytes().to_vec(),
            cert2.as_bytes().to_vec(),
        ];
        verify_cert_chain(&cert_chain, "PEM").unwrap();
        let x5090 = get_cert_from_cert_chain(&cert_chain, 0, "PEM").unwrap();
        let x5091 = get_cert_from_cert_chain(&cert_chain, 1, "PEM").unwrap();
        let x5092 = get_cert_from_cert_chain(&cert_chain, 2, "PEM").unwrap();

        assert_eq!(std::str::from_utf8(&x5090.to_pem().unwrap()), Ok(cert0));
        assert_eq!(std::str::from_utf8(&x5091.to_pem().unwrap()), Ok(cert1));
        assert_eq!(std::str::from_utf8(&x5092.to_pem().unwrap()), Ok(cert2));
    }

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
