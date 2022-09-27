package io.github.dbstarll.certs.model;

import io.github.dbstarll.certs.utils.SecureRandomUtils;
import io.github.dbstarll.utils.lang.security.SignatureAlgorithm;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Date;

import static io.github.dbstarll.certs.utils.CertificationAuthorityUtils.signer;
import static io.github.dbstarll.certs.utils.CertificationAuthorityUtils.uri;

public final class Certificate {
    private final X509CertificateHolder certificateHolder;

    private Certificate(final X509CertificateHolder certificateHolder) {
        this.certificateHolder = certificateHolder;
    }

    /**
     * 写入POM格式的证书.
     *
     * @param out       待写入的writer
     * @param encryptor 加密机
     * @throws IOException io exception
     */
    public void writePEM(final Writer out, final PEMEncryptor encryptor) throws IOException {
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(certificateHolder, encryptor);
        }
    }

    /**
     * 构建一个已签发的证书.
     *
     * @param csr                the Certificate Signing Request
     * @param issuer             签发者
     * @param signatureAlgorithm 签名算法
     * @return 已签发的证书
     * @throws IOException               IOException
     * @throws OperatorCreationException OperatorCreationException
     */

    public static Certificate generate(final CertificateSigningRequest csr,
                                       final CertificationAuthority issuer,
                                       final SignatureAlgorithm signatureAlgorithm)
            throws IOException, OperatorCreationException {
        return generate(csr, issuer.getCsr().getSubject(), issuer.getKeyPair().getPrivate(), signatureAlgorithm);
    }

    /**
     * 构建一个已签发的证书.
     *
     * @param csr                the Certificate Signing Request
     * @param issuer             签发者
     * @param issuerPrivateKey   签发者私钥
     * @param signatureAlgorithm 签名算法
     * @return 已签发的证书
     * @throws IOException               IOException
     * @throws OperatorCreationException OperatorCreationException
     */
    public static Certificate generate(final CertificateSigningRequest csr,
                                       final X500Name issuer, final PrivateKey issuerPrivateKey,
                                       final SignatureAlgorithm signatureAlgorithm)
            throws IOException, OperatorCreationException {
        final BigInteger serial = BigInteger.valueOf(SecureRandomUtils.get().nextLong());
        final Date now = new Date();
        final Date notAfter = DateUtils.addYears(now, 1);
        final X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issuer, serial, now, notAfter, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        // 添加 SAN 扩展
        csr.addSANExtension(builder);

        //添加crl扩展
        final GeneralNames gns = new GeneralNames(uri("http://www.ca.com/crl"));
        final GeneralNames crlIssuer = new GeneralNames(new GeneralName(issuer));
        builder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(
                new DistributionPoint[]{new DistributionPoint(new DistributionPointName(gns), null, crlIssuer)}
        ));

        // 添加aia扩展
        builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                new AccessDescription[]{
                        new AccessDescription(AccessDescription.id_ad_caIssuers, uri("http://www.ca.com/root.crt")),
                        new AccessDescription(AccessDescription.id_ad_ocsp, uri("http://ocsp.com/"))
                }
        ));


//        basicConstraints = critical,CA:TRUE
//        keyUsage = critical,cRLSign,keyCertSign
//        subjectKeyIdentifier = hash
//        authorityKeyIdentifier = keyid:always,issuer


        return new Certificate(builder.build(signer(signatureAlgorithm, issuerPrivateKey)));
    }
}
