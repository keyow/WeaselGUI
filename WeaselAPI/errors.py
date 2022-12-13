TLS_CERTIFICATE_EXPIRED = 45
TLS_UNDEFINED_OR_REJECTED = 51
TLS_SELF_SIGNED_CERTIFICATE = 48

TLS_errors = {
    TLS_CERTIFICATE_EXPIRED: "Certificate expired",
    TLS_UNDEFINED_OR_REJECTED: "Bad decrypt or rejected",
    TLS_SELF_SIGNED_CERTIFICATE: "Self signed certificate in certificate chain"
}
