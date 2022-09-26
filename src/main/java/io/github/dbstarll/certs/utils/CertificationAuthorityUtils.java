package io.github.dbstarll.certs.utils;

import io.github.dbstarll.certs.model.CertificateSigningRequest;
import io.github.dbstarll.certs.model.CertificationAuthority;
import io.github.dbstarll.utils.lang.security.InstanceException;
import io.github.dbstarll.utils.lang.security.KeyPairGeneratorAlgorithm;
import io.github.dbstarll.utils.lang.security.SecurityFactory;
import io.github.dbstarll.utils.lang.security.SignatureAlgorithm;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Date;

public final class CertificationAuthorityUtils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private CertificationAuthorityUtils() {
        // 禁止实例化
    }

    /**
     * 一次性重建所有证书.
     *
     * @throws Exception 任何异常都抛出
     */
    public static void rebuild() throws Exception {
        final CertificationAuthority caRoot = buildOne("ROOT", null, null, 2048, null);
        final CertificationAuthority caServer = buildOne("SERVER", caRoot, 0, 2048, null);
        final CertificationAuthority caClient = buildOne("CLIENT", caRoot, 1, 2048, null);
        final CertificationAuthority caYeeCloud = buildOne("YeeCloud", caClient, 0, 2048, null);
    }

    /**
     * 构建CA证书.
     *
     * @param caName  name of new ca
     * @param issuer  Issuer, The parent certificate
     * @param pathLen pathlen of CA basicConstraints
     * @param numbits numbits of private key
     * @param phrase  private key pass phrase
     * @return CertificationAuthority
     * @throws Exception 任何异常都抛出
     */
    public static CertificationAuthority buildOne(final String caName,
                                                  final CertificationAuthority issuer,
                                                  final Integer pathLen,
                                                  final int numbits,
                                                  final String phrase)
            throws Exception {
//# 创建数据库文件
//    mkdir -p $CA_HOME/.db
//    touch $CA_HOME/.db/index
//    openssl dgst -md5 -r $CA_HOME/.rand >$CA_HOME/.db/serial
//    openssl dgst -md5 -r $CA_HOME/.db/serial >$CA_HOME/.db/crlnumber

//# 复制ca.conf文件
//    sed -e "s/\${ca.name}/$CA_NAME/g" $CERTS_CONF_HOME/ca.conf > $CA_HOME/ca.conf

        // 构建证书私钥
        final KeyPair keyPair = genKeyPair(KeyPairGeneratorAlgorithm.RSA, numbits);

        // 生成证书签发申请
        final X500Name subject;
        //        new X500NameBuilder().addRDN().build();
        if (issuer != null) {
            subject = new X500Name("C=CN,ST=SH,L=SH,O=上海云屹信息技术有限公司,OU=" + caName + ",CN=云屹中间证书-" + caName);
        } else {
            subject = new X500Name("C=CN,ST=SH,L=SH,O=上海云屹信息技术有限公司,OU=" + caName + ",CN=云屹根证书-" + caName);
        }

//        final GeneralNames sanNames = new GeneralNamesBuilder()
//                .addName(new GeneralName(GeneralName.rfc822Name, "ip=6.6.6.6"))
//                .build();
        final CertificateSigningRequest csr = CertificateSigningRequest.generate(keyPair, subject, null, SignatureAlgorithm.SHA256withRSA);

        final X509CertificateHolder crt;
        if (issuer != null) {
            // 签发根证书
// sed -e "s/\${ca.name}/$PARENT_CA/g;s/\${path.len}/$pathlen/g" $CERTS_CONF_HOME/ext/v3_ca_mid > $CA_HOME/extension
            crt = gencrt(issuer, csr);
//    openssl x509 -in $CA_HOME/$CA_NAME.crt -out $CA_HOME/$CA_NAME.cer
//    cat $CA_HOME/$CA_NAME.cer $PARENT_CA_HOME/$PARENT_CA-chain.cer >$CA_HOME/$CA_NAME-chain.cer
//
//    # 构建证书吊销列表
//    gencrl -c $PARENT_CA_HOME/ca.conf$phrase -o $PARENT_CA_HOME/$PARENT_CA.crl || exit 6
        } else {
            // 自行签发根证书
// sed -e "s/\${ca.name}/$CA_NAME/g" $CERTS_CONF_HOME/ext/v3_ca_root > $CA_HOME/extension
            crt = gencrt(new CertificationAuthority(caName, keyPair, csr, null), csr);
//    openssl x509 -in $CA_HOME/$CA_NAME.crt -out $CA_HOME/$CA_NAME.cer
//    cat $CA_HOME/$CA_NAME.cer >$CA_HOME/$CA_NAME-chain.cer
        }
//        System.out.println(crt);

        final CertificationAuthority ca = new CertificationAuthority(caName, keyPair, csr, crt);

        // $CA_NAME.key
        ca.writeKey(debugWriter(), StringUtils.isBlank(phrase) ? null : encryptor("AES-256-CBC", phrase));

        // $CA_NAME.csr
        ca.writeCSR(debugWriter(), null);

        // $CA_NAME.cer
        ca.writeCER(debugWriter(), null);

        return ca;
    }

    private static KeyPair genKeyPair(final KeyPairGeneratorAlgorithm algorithm, final int keySize)
            throws InstanceException, NoSuchAlgorithmException {
        return SecurityFactory.builder(algorithm)
                .keySize(keySize, SecureRandomUtils.get())
                .build().genKeyPair();
    }

    /**
     * 签发证书.
     *
     * @param issuer Issuer, The parent certificate.
     * @param csr    the PKCS#10 certification request.
     * @return 签发好的证书
     */
    public static X509CertificateHolder gencrt(final CertificationAuthority issuer,
                                               final CertificateSigningRequest csr)
            throws OperatorCreationException, CertificateException, IOException {
        final BigInteger serial = BigInteger.valueOf(SecureRandomUtils.get().nextLong());
        final Date now = new Date();
        final Date notAfter = DateUtils.addYears(now, 1);
        final X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                issuer.getCsr().getSubject(), serial, now, notAfter, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        // 添加 SAN 扩展
        csr.addSANExtension(certificateBuilder);

        //添加crl扩展
        final GeneralNames gns = new GeneralNames(uri("http://www.ca.com/crl"));
        final GeneralNames crlIssuer = new GeneralNames(new GeneralName(issuer.getCsr().getSubject()));
        certificateBuilder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(
                new DistributionPoint[]{new DistributionPoint(new DistributionPointName(gns), null, crlIssuer)}
        ));

        // 添加aia扩展
        certificateBuilder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                new AccessDescription[]{
                        new AccessDescription(AccessDescription.id_ad_caIssuers, uri("http://www.ca.com/root.crt")),
                        new AccessDescription(AccessDescription.id_ad_ocsp, uri("http://ocsp.com/"))
                }
        ));


//        basicConstraints = critical,CA:TRUE
//        keyUsage = critical,cRLSign,keyCertSign
//        subjectKeyIdentifier = hash
//        authorityKeyIdentifier = keyid:always,issuer


        return certificateBuilder.build(signer(SignatureAlgorithm.SHA256withRSA, issuer.getKeyPair().getPrivate()));
    }

    /**
     * 构建PEM加密机.
     *
     * @param algorithm 加密算法
     * @param phrase    pass phrase
     * @return PEMEncryptor
     */
    public static PEMEncryptor encryptor(final String algorithm, final String phrase) {
        return new JcePEMEncryptorBuilder(algorithm)
                .setSecureRandom(SecureRandomUtils.get())
                .build(phrase.toCharArray());
    }

    private static GeneralName uri(final String uri) {
        return new GeneralName(GeneralName.uniformResourceIdentifier, uri);
    }

    public static ContentSigner signer(final SignatureAlgorithm algorithm,
                                       final PrivateKey privateKey) throws OperatorCreationException {
        return new JcaContentSignerBuilder(algorithm.name()).setSecureRandom(SecureRandomUtils.get()).build(privateKey);
    }

    private static Writer debugWriter() {
        return new StringWriter() {
            @Override
            public void close() throws IOException {
                super.close();
                System.out.println(this.toString());
            }
        };
    }

    /**
     * 主程序入口.
     *
     * @param args 入参
     * @throws Exception 任何异常都抛出
     */
    public static void main(final String[] args) throws Exception {
        rebuild();
    }
}
