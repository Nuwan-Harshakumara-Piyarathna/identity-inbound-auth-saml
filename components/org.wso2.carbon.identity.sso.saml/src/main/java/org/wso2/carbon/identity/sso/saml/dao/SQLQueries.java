package org.wso2.carbon.identity.sso.saml.dao;

public class SQLQueries {
    private SQLQueries() {

    }

    public static class JDBCSAMLSSODAOSQLQueries {
        public static final String ADD_SAML_APP = "INSERT INTO IDN_SAML2_CONSUMER_APPS " +
                "(ISSUER_NAME, PROP_KEY, PROP_VALUE, TENANT_ID) VALUES (?,?,?,?) ";

        public static final String GET_SAML_APPS = "SELECT * FROM IDN_SAML2_CONSUMER_APPS";

        public static final String GET_SAML_APP_SINGLE_ATTRIBUTE_BY_ISSUER_NAME = "SELECT * FROM IDN_SAML2_CONSUMER_APPS WHERE ISSUER_NAME = ? LIMIT 1";

        public static final String GET_SAML_APP_ALL_ATTRIBUTES_BY_ISSUER_NAME = "SELECT * FROM IDN_SAML2_CONSUMER_APPS WHERE ISSUER_NAME = ?";

        public static final String REMOVE_SAML_APP_BY_ISSUER_NAME = "DELETE FROM IDN_SAML2_CONSUMER_APPS " +
                "WHERE ISSUER_NAME = ?";
    }
}
