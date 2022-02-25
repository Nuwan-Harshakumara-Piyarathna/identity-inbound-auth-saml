package org.wso2.carbon.identity.sso.saml.model;

public class SAMLSSO_Model {
    private int id;
    private String issuer_name;
    private String key_name;
    private String value_name;
    private int tenant_id;

    public SAMLSSO_Model(int id, String issuer_name, String key_name, String value_name, int tenant_id) {
        this.id = id;
        this.issuer_name = issuer_name;
        this.key_name = key_name;
        this.value_name = value_name;
        this.tenant_id = tenant_id;
    }

    public SAMLSSO_Model(String issuer_name, String key_name, String value_name, int tenant_id) {
        this.issuer_name = issuer_name;
        this.key_name = key_name;
        this.value_name = value_name;
        this.tenant_id = tenant_id;
    }

    public int getId() {
        return id;
    }

    public String getIssuer_name() {
        return issuer_name;
    }

    public String getKey_name() {
        return key_name;
    }

    public String getValue_name() {
        return value_name;
    }

    public int getTenant_id() {
        return tenant_id;
    }
}
