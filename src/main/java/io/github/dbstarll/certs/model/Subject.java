package io.github.dbstarll.certs.model;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

import static org.apache.commons.lang3.Validate.matchesPattern;
import static org.apache.commons.lang3.Validate.notBlank;

public final class Subject implements Serializable {
    private static final Logger LOGGER = LoggerFactory.getLogger(Subject.class);

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

    /**
     * get common name.
     *
     * @return common name
     */
    public String getCommon() {
        return common;
    }

    /**
     * set common name.
     *
     * @param common common name
     */
    public void setCommon(final String common) {
        if (StringUtils.isNotBlank(common)) {
            matchesPattern(common, "\\S.{0,63}");
        }
        this.common = common;
    }

    /**
     * get device serial number name.
     *
     * @return device serial number name
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * set device serial number name.
     *
     * @param serialNumber device serial number name
     */
    public void setSerialNumber(final String serialNumber) {
        if (StringUtils.isNotBlank(serialNumber)) {
            matchesPattern(serialNumber, "\\S{1,64}");
        }
        this.serialNumber = serialNumber;
    }

    /**
     * get country code.
     *
     * @return country code
     */
    public String getCountryCode() {
        return countryCode;
    }

    /**
     * set country code.
     *
     * @param countryCode country code
     */
    public void setCountryCode(final String countryCode) {
        if (StringUtils.isNotBlank(countryCode)) {
            matchesPattern(countryCode, "[A-Z]{2}");
        }
        this.countryCode = countryCode;
    }

    /**
     * get locality name(City).
     *
     * @return locality name(City)
     */
    public String getLocality() {
        return locality;
    }

    /**
     * set locality name(City).
     *
     * @param locality locality name(City)
     */
    public void setLocality(final String locality) {
        if (StringUtils.isNotBlank(locality)) {
            matchesPattern(locality, "\\S.{0,63}");
        }
        this.locality = locality;
    }

    /**
     * get state name(Province).
     *
     * @return state name(Province)
     */
    public String getState() {
        return state;
    }

    /**
     * set state name(Province).
     *
     * @param state state name(Province)
     */
    public void setState(final String state) {
        if (StringUtils.isNotBlank(state)) {
            matchesPattern(state, "\\S.{0,63}");
        }
        this.state = state;
    }

    /**
     * get street.
     *
     * @return street
     */
    public String getStreet() {
        return street;
    }

    /**
     * set street.
     *
     * @param street street
     */
    public void setStreet(final String street) {
        if (StringUtils.isNotBlank(street)) {
            matchesPattern(street, "\\S.{0,63}");
        }
        this.street = street;
    }

    /**
     * get organization(Company).
     *
     * @return organization(Company)
     */
    public String getOrganization() {
        return organization;
    }

    /**
     * set organization(Company).
     *
     * @param organization organization(Company)
     */
    public void setOrganization(final String organization) {
        if (StringUtils.isNotBlank(organization)) {
            matchesPattern(organization, "\\S.{0,63}");
        }
        this.organization = organization;
    }

    /**
     * get organizational unit name(Department).
     *
     * @return organizational unit name(Department)
     */
    public String getOrganizationalUnit() {
        return organizationalUnit;
    }

    /**
     * set organizational unit name(Department).
     *
     * @param organizationalUnit organizational unit name(Department)
     */
    public void setOrganizationalUnit(final String organizationalUnit) {
        if (StringUtils.isNotBlank(organizationalUnit)) {
            matchesPattern(organizationalUnit, "\\S.{0,63}");
        }
        this.organizationalUnit = organizationalUnit;
    }

    /**
     * get Title.
     *
     * @return Title
     */
    public String getTitle() {
        return title;
    }

    /**
     * set Title.
     *
     * @param title Title
     */
    public void setTitle(final String title) {
        this.title = title;
    }

    /**
     * get Description.
     *
     * @return Description
     */
    public String getDescription() {
        return description;
    }

    /**
     * set Description.
     *
     * @param description Description
     */
    public void setDescription(final String description) {
        this.description = description;
    }

    X500Name toX500Name() {
        final X500NameBuilder builder = new X500NameBuilder();
        addRequired(builder, BCStyle.CN, getCommon());
        addOptional(builder, BCStyle.C, getCountryCode());
        addOptional(builder, BCStyle.L, getLocality());
        addOptional(builder, BCStyle.ST, getState());
        addOptional(builder, BCStyle.STREET, getStreet());
        addRequired(builder, BCStyle.O, getOrganization());
        addOptional(builder, BCStyle.OU, getOrganizationalUnit());
        addOptional(builder, BCStyle.T, getTitle());
        addOptional(builder, BCStyle.DESCRIPTION, getDescription());
        return builder.build();
    }

    /**
     * 从X500Name构建Subject.
     *
     * @param x500Name x500Name
     * @return Subject
     */
    public static Subject from(final X500Name x500Name) {
        final Subject subject = new Subject();
        for (RDN rdn : x500Name.getRDNs()) {
            final AttributeTypeAndValue tv = rdn.getFirst();
            final ASN1ObjectIdentifier type = tv.getType();
            final String value = tv.getValue().toString();
            if (BCStyle.CN.equals(type)) {
                subject.setCommon(value);
            } else if (BCStyle.SERIALNUMBER.equals(type)) {
                subject.setSerialNumber(value);
            } else if (BCStyle.C.equals(type)) {
                subject.setCountryCode(value);
            } else if (BCStyle.L.equals(type)) {
                subject.setLocality(value);
            } else if (BCStyle.ST.equals(type)) {
                subject.setState(value);
            } else if (BCStyle.STREET.equals(type)) {
                subject.setStreet(value);
            } else if (BCStyle.O.equals(type)) {
                subject.setOrganization(value);
            } else if (BCStyle.OU.equals(type)) {
                subject.setOrganizationalUnit(value);
            } else if (BCStyle.T.equals(type)) {
                subject.setTitle(value);
            } else if (BCStyle.DESCRIPTION.equals(type)) {
                subject.setDescription(value);
            } else {
                LOGGER.warn("unknown X500Name RDN: {} -> {}", type, value);
            }
        }
        return subject;
    }

    private static void addRequired(final X500NameBuilder builder, final ASN1ObjectIdentifier oid, final String value) {
        builder.addRDN(oid, notBlank(value));
    }

    private static void addOptional(final X500NameBuilder builder, final ASN1ObjectIdentifier oid, final String value) {
        if (StringUtils.isNotBlank(value)) {
            builder.addRDN(oid, value);
        }
    }
}
