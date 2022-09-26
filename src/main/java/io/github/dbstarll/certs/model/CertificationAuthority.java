package io.github.dbstarll.certs.model;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.IOException;
import java.io.Serializable;
import java.io.Writer;
import java.security.KeyPair;

public final class CertificationAuthority implements Serializable {
    private final String name;
    private final KeyPair keyPair;
    private final CertificateSigningRequest csr;
    private final X509CertificateHolder crt;

    /**
     * 构建CertificationAuthority对象.
     *
     * @param name    name of ca
     * @param keyPair key pair (a public key and a private key)
     * @param csr     the PKCS#10 certification request.
     * @param crt     the Certificate.
     */
    public CertificationAuthority(final String name,
                                  final KeyPair keyPair,
                                  final CertificateSigningRequest csr,
                                  final X509CertificateHolder crt) {
        this.name = name;
        this.keyPair = keyPair;
        this.csr = csr;
        this.crt = crt;
    }

    public String getName() {
        return name;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public CertificateSigningRequest getCsr() {
        return csr;
    }

    public X509CertificateHolder getCrt() {
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
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(crt, encryptor);
        }
    }
}
