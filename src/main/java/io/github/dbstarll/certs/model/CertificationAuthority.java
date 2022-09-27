package io.github.dbstarll.certs.model;

import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.Serializable;
import java.io.Writer;
import java.security.KeyPair;

public final class CertificationAuthority implements Serializable {
    private final String name;
    private final KeyPair keyPair;
    private final Subject subject;
    private final CertificateSigningRequest csr;
    private final Certificate crt;

    /**
     * 构建CertificationAuthority对象.
     *
     * @param name    name of ca
     * @param keyPair key pair (a public key and a private key)
     * @param subject subject
     * @param csr     the PKCS#10 certification request.
     * @param crt     the Certificate.
     */
    public CertificationAuthority(final String name,
                                  final KeyPair keyPair,
                                  final Subject subject,
                                  final CertificateSigningRequest csr,
                                  final Certificate crt) {
        this.name = name;
        this.keyPair = keyPair;
        this.subject = subject;
        this.csr = csr;
        this.crt = crt;
    }

    String getName() {
        return name;
    }

    KeyPair getKeyPair() {
        return keyPair;
    }

    Subject getSubject() {
        return subject;
    }

    CertificateSigningRequest getCsr() {
        return csr;
    }

    Certificate getCrt() {
        return crt;
    }

    /**
     * 写入POM格式的证书私钥.
     *
     * @param out       待写入的writer
     * @param encryptor 加密机
     * @throws IOException io exception
     */
    public void writeKey(final Writer out, final PEMEncryptor encryptor) throws IOException {
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(keyPair.getPrivate(), encryptor);
        }
    }

    /**
     * 写入POM格式的证书签发申请.
     *
     * @param out       待写入的writer
     * @param encryptor 加密机
     * @throws IOException io exception
     */
    public void writeCSR(final Writer out, final PEMEncryptor encryptor) throws IOException {
        csr.writePEM(out, encryptor);
    }

    /**
     * 写入POM格式的证书.
     *
     * @param out       待写入的writer
     * @param encryptor 加密机
     * @throws IOException io exception
     */
    public void writeCER(final Writer out, final PEMEncryptor encryptor) throws IOException {
        crt.writePEM(out, encryptor);
    }
}
