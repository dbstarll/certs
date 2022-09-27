package io.github.dbstarll.certs.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SubjectTest {
    @Test
    void toX500Name() {
        final Subject subject = new Subject();
        subject.setCommon("云屹根证书-ROOT");
        subject.setCountryCode("CN");
        subject.setState("上海市");
        subject.setLocality("普陀区");
        subject.setOrganization("上海云屹信息技术有限公司");
        subject.setOrganizationalUnit("ROOT");
        assertEquals("CN=云屹根证书-ROOT,C=CN,L=普陀区,ST=上海市,O=上海云屹信息技术有限公司,OU=ROOT", subject.toX500Name().toString());
    }
}