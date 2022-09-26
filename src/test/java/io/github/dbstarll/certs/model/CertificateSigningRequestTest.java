package io.github.dbstarll.certs.model;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CertificateSigningRequestTest {
    @Test
    void readPEM() throws Exception {
        final CertificateSigningRequest csr;
        try (InputStream is = ClassLoader.getSystemResourceAsStream("ROOT.csr")) {
            try (Reader reader = new InputStreamReader(is)) {
                csr = CertificateSigningRequest.readPEM(reader);
            }
        }

        assertNotNull(csr);
        assertNotNull(csr.getSubject());
        assertEquals("C=CN,ST=SH,L=SH,O=上海云屹信息技术有限公司,OU=ROOT,CN=云屹根证书-ROOT", csr.getSubject().toString());
    }
}