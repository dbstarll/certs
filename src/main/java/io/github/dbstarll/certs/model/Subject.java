package io.github.dbstarll.certs.model;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.io.Serializable;

import static org.apache.commons.lang3.Validate.matchesPattern;
import static org.apache.commons.lang3.Validate.notBlank;

public final class Subject implements Serializable {
    /**
     * [2.5.4.3](CN)common name(CompanyName or FirstName LastName) - StringType(SIZE(1..64)).
     *
     * @see org.bouncycastle.asn1.x500.style.BCStyle#CN
     */
    private String common;

    /**
     * [2.5.4.5]device serial number name - StringType(SIZE(1..64)).
     *
     * @see org.bouncycastle.asn1.x500.style.BCStyle#SERIALNUMBER
     */
    private String serialNumber;

    /**
     * [2.5.4.6](C)country code - StringType(SIZE(2)).
     *
     * @see org.bouncycastle.asn1.x500.style.BCStyle#C
     */
    private String countryCode;

    /**
     * [2.5.4.7](L)locality name(City) - StringType(SIZE(1..64)).
     *
     * @see org.bouncycastle.asn1.x500.style.BCStyle#L
     */
    private String locality;

    /**
     * [2.5.4.8](ST)state name(Province) - StringType(SIZE(1..64)).
     *
     * @see org.bouncycastle.asn1.x500.style.BCStyle#ST
     */
    private String state;

    /**
     * [2.5.4.9]street - StringType(SIZE(1..64)).
     *
     * @see org.bouncycastle.asn1.x500.style.BCStyle#STREET
     */
    private String street;

    /**
     * [2.5.4.10](O)organization(Company) - StringType(SIZE(1..64)).
     *
     * @see org.bouncycastle.asn1.x500.style.BCStyle#O
     */
    private String organization;

    /**
     * [2.5.4.11](OU)organizational unit name(Department) - StringType(SIZE(1..64)).
     *
     * @see org.bouncycastle.asn1.x500.style.BCStyle#OU
     */
    private String organizationalUnit;

    /**
     * [2.5.4.12](T)Title - StringType.
     *
     * @see org.bouncycastle.asn1.x500.style.BCStyle#T
     */
    private String title;

    /**
     * [2.5.4.13]Description - StringType.
     *
     * @see org.bouncycastle.asn1.x500.style.BCStyle#DESCRIPTION
     */
    private String description;

    public String getCommon() {
        return common;
    }

    public void setCommon(final String common) {
        if (StringUtils.isNotBlank(common)) {
            matchesPattern(common, "\\S.{0,63}");
        }
        this.common = common;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(final String serialNumber) {
        if (StringUtils.isNotBlank(serialNumber)) {
            matchesPattern(serialNumber, "\\S{1,64}");
        }
        this.serialNumber = serialNumber;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public void setCountryCode(final String countryCode) {
        if (StringUtils.isNotBlank(countryCode)) {
            matchesPattern(countryCode, "[A-Z]{2}");
        }
        this.countryCode = countryCode;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(final String locality) {
        if (StringUtils.isNotBlank(locality)) {
            matchesPattern(locality, "\\S.{0,63}");
        }
        this.locality = locality;
    }

    public String getState() {
        return state;
    }

    public void setState(final String state) {
        if (StringUtils.isNotBlank(state)) {
            matchesPattern(state, "\\S.{0,63}");
        }
        this.state = state;
    }

    public String getStreet() {
        return street;
    }

    public void setStreet(final String street) {
        if (StringUtils.isNotBlank(street)) {
            matchesPattern(street, "\\S.{0,63}");
        }
        this.street = street;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(final String organization) {
        if (StringUtils.isNotBlank(organization)) {
            matchesPattern(organization, "\\S.{0,63}");
        }
        this.organization = organization;
    }

    public String getOrganizationalUnit() {
        return organizationalUnit;
    }

    public void setOrganizationalUnit(final String organizationalUnit) {
        if (StringUtils.isNotBlank(organizationalUnit)) {
            matchesPattern(organizationalUnit, "\\S.{0,63}");
        }
        this.organizationalUnit = organizationalUnit;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(final String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(final String description) {
        this.description = description;
    }

    X500Name toX500Name() {
        final X500NameBuilder builder = new X500NameBuilder();
        addRequired(builder, BCStyle.CN, common);
        addOptional(builder, BCStyle.C, countryCode);
        addOptional(builder, BCStyle.L, locality);
        addOptional(builder, BCStyle.ST, state);
        addOptional(builder, BCStyle.STREET, street);
        addRequired(builder, BCStyle.O, organization);
        addOptional(builder, BCStyle.OU, organizationalUnit);
        addOptional(builder, BCStyle.T, title);
        addOptional(builder, BCStyle.DESCRIPTION, description);
        return builder.build();
    }

    private void addRequired(final X500NameBuilder builder, final ASN1ObjectIdentifier oid, final String value) {
        builder.addRDN(oid, notBlank(value));
    }

    private static void addOptional(final X500NameBuilder builder, final ASN1ObjectIdentifier oid, final String value) {
        if (StringUtils.isNotBlank(value)) {
            builder.addRDN(oid, value);
        }
    }
}
