package org.wso2.carbon.identity.sso.saml.dao;

import org.springframework.jdbc.core.ResultSetExtractor;
import org.wso2.carbon.consent.mgt.core.util.JdbcUtils;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.RowMapper;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.sso.saml.exception.ArtifactBindingException;
import org.wso2.carbon.identity.sso.saml.model.SAMLSSO_Model;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class JDBCSAMLSSOAppDAO {
    public void addSAMLServiceProvider(List<SAMLSSO_Model> list) throws ArtifactBindingException {
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        try {
            for (SAMLSSO_Model item:list) {
                jdbcTemplate.executeInsert(SQLQueries.JDBCSAMLSSODAOSQLQueries.ADD_SAML_APP, (preparedStatement -> {
                    preparedStatement.setString(1, item.getIssuer_name());
                    preparedStatement.setString(2, item.getKey_name());
                    preparedStatement.setString(3, item.getValue_name());
                    preparedStatement.setInt(4, item.getTenant_id());
                }), item, true);
            }

        } catch (DataAccessException e) {
            throw new ArtifactBindingException("Error while storing SAML2 SSO SP information.");
        }
    }

    public SAMLSSO_Model findSAMLServiceProvider(String issuer) throws ArtifactBindingException {
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        SAMLSSO_Model result;
        try {
            result = jdbcTemplate.fetchSingleRecord(SQLQueries.JDBCSAMLSSODAOSQLQueries.GET_SAML_APP_BY_ISSUER_NAME, new RowMapper<SAMLSSO_Model>() {
                        @Override
                        public SAMLSSO_Model mapRow(ResultSet resultSet, int i) throws SQLException {
                            return new SAMLSSO_Model(
                                    resultSet.getInt(1),
                                    resultSet.getString(2),
                                    resultSet.getString(3),
                                    resultSet.getString(4),
                                    resultSet.getInt(5));
                        }
                    },
                    (preparedStatement -> {
                        preparedStatement.setString(1, issuer);

                    }));
        } catch (DataAccessException e) {
            throw new ArtifactBindingException("Error while retrieving SAML2 artifact information.", e);
        }
        return result;
    }


    public void removeServiceProvider(String issuer) throws ArtifactBindingException {
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        try {
            jdbcTemplate.executeUpdate(SQLQueries.JDBCSAMLSSODAOSQLQueries.REMOVE_SAML_APP_BY_ISSUER_NAME, preparedStatement ->
                    preparedStatement.setString(1, issuer));
        } catch (DataAccessException e) {
            throw new ArtifactBindingException("Error while deleting SAML2 SSO provider information for ISSUER: " +
                    issuer, e);
        }
    }

    public ArrayList<SAMLSSO_Model> getAllServiceProviders() {
        JdbcTemplate jdbcTemplate = JdbcUtils.getNewTemplate();
        List<SAMLSSO_Model> list;
        try {
            list = jdbcTemplate.executeQuery(SQLQueries.JDBCSAMLSSODAOSQLQueries.GET_SAML_APPS, new RowMapper<SAMLSSO_Model>() {
                        @Override
                        public SAMLSSO_Model mapRow(ResultSet resultSet, int i) throws SQLException {
                            return new SAMLSSO_Model(
                                    resultSet.getInt(1),
                                    resultSet.getString(2),
                                    resultSet.getString(3),
                                    resultSet.getString(4),
                                    resultSet.getInt(5)
                            );
                        }
                    }
            );
        } catch (DataAccessException e) {
            throw new RuntimeException(e);
        }
        return (ArrayList<SAMLSSO_Model>) list;
    }
}
