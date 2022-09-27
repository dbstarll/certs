package io.github.dbstarll.certs.model;

import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 测试Subject.
 */
public class SubjectTest {
    @Test
    void toX500Name() {
        final Subject subject = new Subject();
        subject.setCommon("云屹根证书-ROOT");
        subject.setCountryCode("CN");
        subject.setState("上海市");
        subject.setLocality("普陀区");
        subject.setOrganization("上海云屹信息技术有限公司");
        subject.setOrganizationalUnit("ROOT");
        final X500Name x500Name = subject.toX500Name();
        assertEquals("CN=云屹根证书-ROOT,C=CN,L=普陀区,ST=上海市,O=上海云屹信息技术有限公司,OU=ROOT", x500Name.toString());

        final Subject second = Subject.from(x500Name);
        assertEquals("CN=云屹根证书-ROOT,C=CN,L=普陀区,ST=上海市,O=上海云屹信息技术有限公司,OU=ROOT", second.toX500Name().toString());
    }
}