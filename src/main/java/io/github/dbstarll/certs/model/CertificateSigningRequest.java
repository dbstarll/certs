package io.github.dbstarll.certs.model;

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

import static io.github.dbstarll.certs.utils.CertificationAuthorityUtils.signer;

/**
 * 证书签发申请(Certificate Signing Request).
 */
public final class CertificateSigningRequest {
    private final PKCS10CertificationRequest certificationRequest;

    private CertificateSigningRequest(final PKCS10CertificationRequest certificationRequest) {
        this.certificationRequest = certificationRequest;
    }

    X500Name getSubject() {
        return certificationRequest.getSubject();
    }

    SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return certificationRequest.getSubjectPublicKeyInfo();
    }

    X509v3CertificateBuilder addSANExtension(final X509v3CertificateBuilder certificateBuilder) throws CertIOException {
        final Extensions extensions = certificationRequest.getRequestedExtensions();
        if (extensions != null) {
            final Extension ext = extensions.getExtension(Extension.subjectAlternativeName);
            if (ext != null) {
                certificateBuilder.addExtension(ext);
            }
        }
        return certificateBuilder;
    }

    /**
     * 写入POM格式的证书签发申请.
     *
     * @param out       待写入的writer
     * @param encryptor 加密机
     * @throws IOException io exception
     */
    public void writePEM(final Writer out, final PEMEncryptor encryptor) throws IOException {
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(certificationRequest, encryptor);
        }
    }

    /**
     * 读取POM格式的证书签发申请.
     *
     * @param reader 待读取的reader
     * @return 证书签发申请
     * @throws IOException io exception
     */
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

    /**
     * 构建一个证书签发申请.
     *
     * @param keyPair            key pair (a public key and a private key)
     * @param subject            an X500Name containing the subject associated with the request we are building.
     * @param sanNames           SAN(Subject Alternative Name)
     * @param signatureAlgorithm 签名算法
     * @return 证书签发申请
     * @throws IOException               IOException
     * @throws OperatorCreationException OperatorCreationException
     */
    public static CertificateSigningRequest generate(final KeyPair keyPair, final Subject subject,
                                                     final GeneralNames sanNames,
                                                     final SignatureAlgorithm signatureAlgorithm)
            throws IOException, OperatorCreationException {
        final PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
                subject.toX500Name(), keyPair.getPublic());

        if (sanNames != null && sanNames.getNames().length > 0) {
            // SAN(Subject Alternative Name)扩展
            final ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, sanNames);
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        }

        return new CertificateSigningRequest(builder.build(signer(signatureAlgorithm, keyPair.getPrivate())));
    }
}
