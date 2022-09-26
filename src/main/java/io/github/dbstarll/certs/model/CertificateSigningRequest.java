package io.github.dbstarll.certs.model;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;

/**
 * 证书签发申请(Certificate Signing Request).
 */
public final class CertificateSigningRequest {
    private final PKCS10CertificationRequest request;

    private CertificateSigningRequest(final PKCS10CertificationRequest request) {
        this.request = request;
    }

    public X500Name getSubject() {
        return request.getSubject();
    }

    public static CertificateSigningRequest from(final PKCS10CertificationRequest request) {
        return new CertificateSigningRequest(request);
    }

    public void writePEM(final Writer out, final PEMEncryptor encryptor) throws IOException {
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(request, encryptor);
        }
    }

    public static CertificateSigningRequest readPEM(final Reader reader) throws IOException {
        try (PEMParser parser = new PEMParser(reader)) {
            final Object obj = parser.readObject();
            if (obj == null) {
                throw new PEMException("no objects left");
            } else if (obj instanceof PKCS10CertificationRequest) {
                return from((PKCS10CertificationRequest) obj);
            } else {
                throw new PEMException("not a Certificate Signing Request");
            }
        }
    }
}