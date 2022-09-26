package io.github.dbstarll.certs.model;

import io.github.dbstarll.certs.utils.CertificationAuthorityUtils;
import io.github.dbstarll.utils.lang.security.SignatureAlgorithm;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.security.KeyPair;

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

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return request.getSubjectPublicKeyInfo();
    }

    public X509v3CertificateBuilder addSANExtension(final X509v3CertificateBuilder certificateBuilder) throws CertIOException {
        final Extensions extensions = request.getRequestedExtensions();
        if (extensions != null) {
            final Extension ext = extensions.getExtension(Extension.subjectAlternativeName);
            if (ext != null) {
                certificateBuilder.addExtension(ext);
            }
        }
        return certificateBuilder;
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
                return new CertificateSigningRequest((PKCS10CertificationRequest) obj);
            } else {
                throw new PEMException("not a Certificate Signing Request");
            }
        }
    }

    public static CertificateSigningRequest generate(final KeyPair keyPair, final X500Name subject,
                                                     final GeneralNames sanNames, final SignatureAlgorithm algorithm)
            throws IOException, OperatorCreationException {
        final PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());

        if (sanNames != null && sanNames.getNames().length > 0) {
            // SAN(Subject Alternative Name)扩展
            final ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, sanNames);
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        }

        return new CertificateSigningRequest(builder.build(CertificationAuthorityUtils.signer(algorithm, keyPair.getPrivate())));
    }
}
