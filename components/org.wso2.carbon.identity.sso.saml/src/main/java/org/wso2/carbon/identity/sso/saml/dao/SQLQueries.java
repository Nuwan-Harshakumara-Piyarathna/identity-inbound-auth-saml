package org.wso2.carbon.identity.sso.saml.dao;

public class SQLQueries {
    private SQLQueries() {

    }

    public static class JDBCSAMLSSODAOSQLQueries {
        public static final String ADD_SAML_APP = "INSERT INTO SAML_SSO_SP " +
                "(ISSUER_NAME, KEY_NAME, VALUE_NAME, TENANT_ID) VALUES (?,?,?,?) ";

        public static final String GET_SAML_APPS = "SELECT * FROM SAML_SSO_SP";

        public static final String GET_SAML_APP_SINGLE_ATTRIBUTE_BY_ISSUER_NAME = "SELECT * FROM SAML_SSO_SP WHERE ISSUER_NAME = ? LIMIT 1";

        public static final String GET_SAML_APP_ALL_ATTRIBUTES_BY_ISSUER_NAME = "SELECT * FROM SAML_SSO_SP WHERE ISSUER_NAME = ?";

        public static final String REMOVE_SAML_APP_BY_ISSUER_NAME = "DELETE FROM SAML_SSO_SP " +
                "WHERE ISSUER_NAME = ?";
    }
}
