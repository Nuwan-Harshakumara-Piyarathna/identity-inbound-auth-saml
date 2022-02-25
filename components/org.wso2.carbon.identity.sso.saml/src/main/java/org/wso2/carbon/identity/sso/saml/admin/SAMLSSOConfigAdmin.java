/*
 * Copyright (c) 2007, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml.admin;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml1.core.NameIdentifier;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.persistence.IdentityPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sp.metadata.saml2.exception.InvalidMetadataException;
import org.wso2.carbon.identity.sp.metadata.saml2.util.Parser;
import org.wso2.carbon.identity.sso.saml.Error;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.dao.JDBCSAMLSSOAppDAO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderInfoDTO;
import org.wso2.carbon.identity.sso.saml.exception.ArtifactBindingException;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ClientException;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponent;
import org.wso2.carbon.identity.sso.saml.model.SAMLSSO_Model;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.session.UserRegistry;

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.util.*;

import static org.wso2.carbon.identity.sso.saml.Error.CONFLICTING_SAML_ISSUER;
import static org.wso2.carbon.identity.sso.saml.Error.INVALID_REQUEST;

/**
 * This class is used for managing SAML SSO providers. Adding, retrieving and removing service
 * providers are supported here.
 * In addition to that logic for generating key pairs for tenants except for tenant 0, is included
 * here.
 */
public class SAMLSSOConfigAdmin {

    private static final Log log = LogFactory.getLog(SAMLSSOConfigAdmin.class);
    private UserRegistry registry;

    public SAMLSSOConfigAdmin(Registry userRegistry) {
        registry = (UserRegistry) userRegistry;
    }

    /**
     * Add a new service provider
     *
     * @param serviceProviderDTO service Provider DTO
     * @return true if successful, false otherwise
     * @throws IdentityException if fails to load the identity persistence manager
     */
    public boolean addRelyingPartyServiceProvider(SAMLSSOServiceProviderDTO serviceProviderDTO) throws IdentityException {

        SAMLSSOServiceProviderDO serviceProviderDO = createSAMLSSOServiceProviderDO(serviceProviderDTO);
        try {
            JDBCSAMLSSOAppDAO jdbcsamlssoAppDAO = new JDBCSAMLSSOAppDAO();
            String issuer = getIssuerWithQualifier(serviceProviderDO);

            SAMLSSO_Model existingSamlSsoServiceProvider = jdbcsamlssoAppDAO.findSAMLServiceProvider(issuer);

            if (existingSamlSsoServiceProvider != null) {
                String message = "A Service Provider with the name " + issuer + " is already loaded" +
                        " from the file system.";
                log.error(message);
                return false;
            }
            List<SAMLSSO_Model> list = convertServiceProviderToList(serviceProviderDTO);
            jdbcsamlssoAppDAO.addSAMLServiceProvider(list);
            return true;
        }  catch (ArtifactBindingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Add a new service provider
     *
     * @param serviceProviderDTO service Provider DTO
     * @return true if successful, false otherwise
     * @throws IdentityException if fails to load the identity persistence manager
     */
    public SAMLSSOServiceProviderDTO addSAMLServiceProvider(SAMLSSOServiceProviderDTO serviceProviderDTO)
            throws IdentityException {

        SAMLSSOServiceProviderDO serviceProviderDO = createSAMLSSOServiceProviderDO(serviceProviderDTO);
        try {
            // Issuer value of the created SAML SP.
            String issuer = getIssuerWithQualifier(serviceProviderDO);
            SAMLSSOServiceProviderDO samlssoServiceProviderDO = SSOServiceProviderConfigManager.getInstance().
                    getServiceProvider(issuer);
            if (samlssoServiceProviderDO != null) {
                String message = "A Service Provider with the name: " + issuer + " is already loaded from the file system.";
                throw buildClientException(CONFLICTING_SAML_ISSUER, message);
            }
            return persistSAMLServiceProvider(serviceProviderDO);
        } catch (IdentitySAML2ClientException e){
            throw e;
        } catch (IdentityException e) {
            String message = "Error obtaining a registry for adding a new service provider";
            throw new IdentityException(message, e);
        }
    }

    private String getIssuerWithQualifier(SAMLSSOServiceProviderDO serviceProviderDO) {

        return SAMLSSOUtil.getIssuerWithQualifier(serviceProviderDO.getIssuer(), serviceProviderDO.getIssuerQualifier());
    }

    private SAMLSSOServiceProviderDTO persistSAMLServiceProvider(SAMLSSOServiceProviderDO samlssoServiceProviderDO)
            throws IdentityException {

        IdentityPersistenceManager persistenceManager = IdentityPersistenceManager.getPersistanceManager();
        boolean response = persistenceManager.addServiceProvider(registry, samlssoServiceProviderDO);
        if (response) {
            return createSAMLSSOServiceProviderDTO(samlssoServiceProviderDO);
        } else {
            String issuer = samlssoServiceProviderDO.getIssuer();
            String msg = "An application with the SAML issuer: " + issuer + " already exists in tenantDomain: " +
                    getTenantDomain();
            throw buildClientException(CONFLICTING_SAML_ISSUER, msg);
        }
    }

    /**
     * Save Certificate To Key Store
     *
     * @param serviceProviderDO Service provider data object
     * @throws Exception exception
     */
    private void saveCertificateToKeyStore(SAMLSSOServiceProviderDO serviceProviderDO) throws Exception {

        KeyStoreManager manager = KeyStoreManager.getInstance(registry.getTenantId(), IdentitySAMLSSOServiceComponent
                .getServerConfigurationService(), IdentityTenantUtil.getRegistryService());

        if (MultitenantConstants.SUPER_TENANT_ID == registry.getTenantId()) {

            KeyStore keyStore = manager.getPrimaryKeyStore();

            // Admin should manually add the service provider signing certificate to the keystore file.
            // If the certificate is available we will set the alias of that certificate.
            String alias = keyStore.getCertificateAlias(serviceProviderDO.getX509Certificate());
            if (!StringUtils.isBlank(alias)) {
                serviceProviderDO.setCertAlias(alias);
            } else {
                serviceProviderDO.setCertAlias(null);
            }
        } else {

            String keyStoreName = getKeyStoreName(registry.getTenantId());
            KeyStore keyStore = manager.getKeyStore(keyStoreName);

            // Add new certificate
            keyStore.setCertificateEntry(serviceProviderDO.getIssuer(), serviceProviderDO.getX509Certificate());
            manager.updateKeyStore(keyStoreName, keyStore);
        }
    }

    /**
     * This method returns the key store file name from the domain Name
     *
     * @return key store name
     */
    private String getKeyStoreName(int tenantId) {

        String ksName = IdentityTenantUtil.getTenantDomain(tenantId).replace(".", "-");
        return (ksName + ".jks");
    }

    /**
     * upload SAML SSO service provider metadata directly
     *
     * @param metadata
     * @return
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDTO uploadRelyingPartyServiceProvider(String metadata) throws IdentityException {

        IdentityPersistenceManager persistenceManager = IdentityPersistenceManager.getPersistanceManager();
        Parser parser = new Parser(registry);
        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();

        try {
            //pass metadata to samlSSOServiceProvider object
            samlssoServiceProviderDO = parser.parse(metadata, samlssoServiceProviderDO);
        } catch (InvalidMetadataException e) {
            throw buildClientException(INVALID_REQUEST, "Error parsing SAML SP metadata.", e);
        }

        if (samlssoServiceProviderDO.getX509Certificate() != null) {
            try {
                //save certificate
                this.saveCertificateToKeyStore(samlssoServiceProviderDO);
            } catch (Exception e) {
                throw new IdentityException("Error occurred while setting certificate and alias", e);
            }
        }

        return persistSAMLServiceProvider(samlssoServiceProviderDO);
    }

    private IdentitySAML2ClientException buildClientException(Error error, String message) {

        return new IdentitySAML2ClientException(error.getErrorCode(), message);
    }

    private IdentitySAML2ClientException buildClientException(Error error, String message, Exception e) {

        return new IdentitySAML2ClientException(error.getErrorCode(), message, e);
    }

    private SAMLSSOServiceProviderDO createSAMLSSOServiceProviderDO(SAMLSSOServiceProviderDTO serviceProviderDTO) throws IdentityException {
        SAMLSSOServiceProviderDO serviceProviderDO = new SAMLSSOServiceProviderDO();

        validateIssuer(serviceProviderDTO.getIssuer());
        serviceProviderDO.setIssuer(serviceProviderDTO.getIssuer());

        validateIssuerQualifier(serviceProviderDTO.getIssuerQualifier());
        serviceProviderDO.setIssuerQualifier(serviceProviderDTO.getIssuerQualifier());

        serviceProviderDO.setAssertionConsumerUrls(serviceProviderDTO.getAssertionConsumerUrls());
        serviceProviderDO.setDefaultAssertionConsumerUrl(serviceProviderDTO.getDefaultAssertionConsumerUrl());
        serviceProviderDO.setCertAlias(serviceProviderDTO.getCertAlias());
        serviceProviderDO.setDoSingleLogout(serviceProviderDTO.isDoSingleLogout());
        serviceProviderDO.setDoFrontChannelLogout(serviceProviderDTO.isDoFrontChannelLogout());
        serviceProviderDO.setFrontChannelLogoutBinding(serviceProviderDTO.getFrontChannelLogoutBinding());
        serviceProviderDO.setSloResponseURL(serviceProviderDTO.getSloResponseURL());
        serviceProviderDO.setSloRequestURL(serviceProviderDTO.getSloRequestURL());
        serviceProviderDO.setLoginPageURL(serviceProviderDTO.getLoginPageURL());
        serviceProviderDO.setDoSignResponse(serviceProviderDTO.isDoSignResponse());
        /*
        According to the spec, "The <Assertion> element(s) in the <Response> MUST be signed". Therefore we should not
        reply on any property to decide this behaviour. Hence the property is set to sign by default.
        */
        serviceProviderDO.setDoSignAssertions(true);
        serviceProviderDO.setNameIdClaimUri(serviceProviderDTO.getNameIdClaimUri());
        serviceProviderDO.setSigningAlgorithmUri(serviceProviderDTO.getSigningAlgorithmURI());
        serviceProviderDO.setDigestAlgorithmUri(serviceProviderDTO.getDigestAlgorithmURI());
        serviceProviderDO.setAssertionEncryptionAlgorithmUri(serviceProviderDTO.getAssertionEncryptionAlgorithmURI());
        serviceProviderDO.setKeyEncryptionAlgorithmUri(serviceProviderDTO.getKeyEncryptionAlgorithmURI());
        serviceProviderDO.setAssertionQueryRequestProfileEnabled(serviceProviderDTO
                .isAssertionQueryRequestProfileEnabled());
        serviceProviderDO.setSupportedAssertionQueryRequestTypes(serviceProviderDTO.getSupportedAssertionQueryRequestTypes());
        serviceProviderDO.setEnableSAML2ArtifactBinding(serviceProviderDTO.isEnableSAML2ArtifactBinding());
        serviceProviderDO.setDoValidateSignatureInArtifactResolve(serviceProviderDTO
                .isDoValidateSignatureInArtifactResolve());
        if (serviceProviderDTO.getNameIDFormat() == null) {
            serviceProviderDTO.setNameIDFormat(NameIdentifier.EMAIL);
        } else {
            serviceProviderDTO.setNameIDFormat(serviceProviderDTO.getNameIDFormat().replace("/", ":"));
        }

        serviceProviderDO.setNameIDFormat(serviceProviderDTO.getNameIDFormat());

        if (serviceProviderDTO.isEnableAttributeProfile()) {
            String attributeConsumingIndex = serviceProviderDTO.getAttributeConsumingServiceIndex();
            if (StringUtils.isNotEmpty(attributeConsumingIndex)) {
                serviceProviderDO.setAttributeConsumingServiceIndex(attributeConsumingIndex);
            } else {
                serviceProviderDO.setAttributeConsumingServiceIndex(Integer.toString(IdentityUtil.getRandomInteger()));
            }
            serviceProviderDO.setEnableAttributesByDefault(serviceProviderDTO.isEnableAttributesByDefault());
        } else {
            serviceProviderDO.setAttributeConsumingServiceIndex("");
            if (serviceProviderDO.isEnableAttributesByDefault()) {
                log.warn("Enable Attribute Profile must be selected to activate it by default. " +
                        "EnableAttributesByDefault will be disabled.");
            }
            serviceProviderDO.setEnableAttributesByDefault(false);
        }

        if (serviceProviderDTO.getRequestedAudiences() != null && serviceProviderDTO.getRequestedAudiences().length != 0) {
            serviceProviderDO.setRequestedAudiences(serviceProviderDTO.getRequestedAudiences());
        }
        if (serviceProviderDTO.getRequestedRecipients() != null && serviceProviderDTO.getRequestedRecipients().length != 0) {
            serviceProviderDO.setRequestedRecipients(serviceProviderDTO.getRequestedRecipients());
        }
        serviceProviderDO.setIdPInitSSOEnabled(serviceProviderDTO.isIdPInitSSOEnabled());
        serviceProviderDO.setIdPInitSLOEnabled(serviceProviderDTO.isIdPInitSLOEnabled());
        serviceProviderDO.setIdpInitSLOReturnToURLs(serviceProviderDTO.getIdpInitSLOReturnToURLs());
        serviceProviderDO.setDoEnableEncryptedAssertion(serviceProviderDTO.isDoEnableEncryptedAssertion());
        serviceProviderDO.setDoValidateSignatureInRequests(serviceProviderDTO.isDoValidateSignatureInRequests());
        serviceProviderDO.setIdpEntityIDAlias(serviceProviderDTO.getIdpEntityIDAlias());
        return serviceProviderDO;
    }

    private void validateIssuerQualifier(String issuerQualifier) throws IdentitySAML2ClientException {

        if (StringUtils.isNotBlank(issuerQualifier) && issuerQualifier.contains("@")) {
            String message = "\'@\' is a reserved character. Cannot be used for Service Provider Qualifier Value.";
            throw buildClientException(INVALID_REQUEST, message);
        }
    }

    private void validateIssuer(String issuer) throws IdentitySAML2ClientException {

        if (StringUtils.isBlank(issuer)) {
            throw buildClientException(INVALID_REQUEST, "A value for the Issuer is mandatory.");
        }

        if (issuer.contains("@")) {
            String message = "\'@\' is a reserved character. Cannot be used for Service Provider Entity ID.";
            throw buildClientException(INVALID_REQUEST, message);
        }
    }

    private SAMLSSOServiceProviderDTO createSAMLSSOServiceProviderDTO(SAMLSSOServiceProviderDO serviceProviderDO)
            throws IdentityException {
        SAMLSSOServiceProviderDTO serviceProviderDTO = new SAMLSSOServiceProviderDTO();

        validateIssuer(serviceProviderDO.getIssuer());
        serviceProviderDTO.setIssuer(serviceProviderDO.getIssuer());

        validateIssuerQualifier(serviceProviderDO.getIssuerQualifier());
        serviceProviderDTO.setIssuerQualifier(serviceProviderDO.getIssuerQualifier());

        serviceProviderDTO.setAssertionConsumerUrls(serviceProviderDO.getAssertionConsumerUrls());
        serviceProviderDTO.setDefaultAssertionConsumerUrl(serviceProviderDO.getDefaultAssertionConsumerUrl());
        serviceProviderDTO.setCertAlias(serviceProviderDO.getCertAlias());

        try {

            if (serviceProviderDO.getX509Certificate() != null) {
                serviceProviderDTO.setCertificateContent(IdentityUtil.convertCertificateToPEM(
                        serviceProviderDO.getX509Certificate()));
            }
        } catch (CertificateException e) {
            throw new IdentityException("An error occurred while converting the application certificate to " +
                    "PEM content.", e);
        }

        serviceProviderDTO.setDoSingleLogout(serviceProviderDO.isDoSingleLogout());
        serviceProviderDTO.setDoFrontChannelLogout(serviceProviderDO.isDoFrontChannelLogout());
        serviceProviderDTO.setFrontChannelLogoutBinding(serviceProviderDO.getFrontChannelLogoutBinding());
        serviceProviderDTO.setLoginPageURL(serviceProviderDO.getLoginPageURL());
        serviceProviderDTO.setSloRequestURL(serviceProviderDO.getSloRequestURL());
        serviceProviderDTO.setSloResponseURL(serviceProviderDO.getSloResponseURL());
        serviceProviderDTO.setDoSignResponse(serviceProviderDO.isDoSignResponse());
        /*
        According to the spec, "The <Assertion> element(s) in the <Response> MUST be signed". Therefore we should not
        reply on any property to decide this behaviour. Hence the property is set to sign by default.
        */
        serviceProviderDTO.setDoSignAssertions(true);
        serviceProviderDTO.setNameIdClaimUri(serviceProviderDO.getNameIdClaimUri());
        serviceProviderDTO.setSigningAlgorithmURI(serviceProviderDO.getSigningAlgorithmUri());
        serviceProviderDTO.setDigestAlgorithmURI(serviceProviderDO.getDigestAlgorithmUri());
        serviceProviderDTO.setAssertionEncryptionAlgorithmURI(serviceProviderDO.getAssertionEncryptionAlgorithmUri());
        serviceProviderDTO.setKeyEncryptionAlgorithmURI(serviceProviderDO.getKeyEncryptionAlgorithmUri());
        serviceProviderDTO.setAssertionQueryRequestProfileEnabled(serviceProviderDO
                .isAssertionQueryRequestProfileEnabled());
        serviceProviderDTO.setSupportedAssertionQueryRequestTypes(serviceProviderDO
                .getSupportedAssertionQueryRequestTypes());
        serviceProviderDTO.setEnableAttributesByDefault(serviceProviderDO.isEnableAttributesByDefault());
        serviceProviderDTO.setEnableSAML2ArtifactBinding(serviceProviderDO.isEnableSAML2ArtifactBinding());
        serviceProviderDTO.setDoValidateSignatureInArtifactResolve(serviceProviderDO
                .isDoValidateSignatureInArtifactResolve());

        if (serviceProviderDO.getNameIDFormat() == null) {
            serviceProviderDO.setNameIDFormat(NameIdentifier.EMAIL);
        } else {
            serviceProviderDO.setNameIDFormat(serviceProviderDO.getNameIDFormat().replace("/", ":"));
        }

        serviceProviderDTO.setNameIDFormat(serviceProviderDO.getNameIDFormat());

        if (StringUtils.isNotBlank(serviceProviderDO.getAttributeConsumingServiceIndex())) {
            serviceProviderDTO.setAttributeConsumingServiceIndex(serviceProviderDO.getAttributeConsumingServiceIndex());
            serviceProviderDTO.setEnableAttributeProfile(true);
        }

        if (serviceProviderDO.getRequestedAudiences() != null && serviceProviderDO.getRequestedAudiences().length !=
                0) {
            serviceProviderDTO.setRequestedAudiences(serviceProviderDO.getRequestedAudiences());
        }
        if (serviceProviderDO.getRequestedRecipients() != null && serviceProviderDO.getRequestedRecipients().length
                != 0) {
            serviceProviderDTO.setRequestedRecipients(serviceProviderDO.getRequestedRecipients());
        }
        serviceProviderDTO.setIdPInitSSOEnabled(serviceProviderDO.isIdPInitSSOEnabled());
        serviceProviderDTO.setDoEnableEncryptedAssertion(serviceProviderDO.isDoEnableEncryptedAssertion());
        serviceProviderDTO.setDoValidateSignatureInRequests(serviceProviderDO.isDoValidateSignatureInRequests());
        serviceProviderDTO.setIdpEntityIDAlias(serviceProviderDO.getIdpEntityIDAlias());
        return serviceProviderDTO;
    }

    /**
     * Retrieve all the relying party service providers
     *
     * @return set of RP Service Providers + file path of pub. key of generated key pair
     */
        public SAMLSSOServiceProviderInfoDTO getServiceProviders_old() throws IdentityException {
        SAMLSSOServiceProviderDTO[] serviceProviders = null;
        try {
            IdentityPersistenceManager persistenceManager = IdentityPersistenceManager
                    .getPersistanceManager();
            SAMLSSOServiceProviderDO[] providersSet = persistenceManager.getServiceProviders(registry);
            serviceProviders = new SAMLSSOServiceProviderDTO[providersSet.length];

            for (int i = 0; i < providersSet.length; i++) {
                SAMLSSOServiceProviderDO providerDO = providersSet[i];
                SAMLSSOServiceProviderDTO providerDTO = new SAMLSSOServiceProviderDTO();
                providerDTO.setIssuer(providerDO.getIssuer());
                providerDTO.setIssuerQualifier(providerDO.getIssuerQualifier());
                providerDTO.setAssertionConsumerUrls(providerDO.getAssertionConsumerUrls());
                providerDTO.setDefaultAssertionConsumerUrl(providerDO.getDefaultAssertionConsumerUrl());
                providerDTO.setSigningAlgorithmURI(providerDO.getSigningAlgorithmUri());
                providerDTO.setDigestAlgorithmURI(providerDO.getDigestAlgorithmUri());
                providerDTO.setAssertionEncryptionAlgorithmURI(providerDO.getAssertionEncryptionAlgorithmUri());
                providerDTO.setKeyEncryptionAlgorithmURI(providerDO.getKeyEncryptionAlgorithmUri());
                providerDTO.setCertAlias(providerDO.getCertAlias());
                providerDTO.setAttributeConsumingServiceIndex(providerDO.getAttributeConsumingServiceIndex());

                if (StringUtils.isNotBlank(providerDO.getAttributeConsumingServiceIndex())) {
                    providerDTO.setEnableAttributeProfile(true);
                }

                providerDTO.setDoSignResponse(providerDO.isDoSignResponse());
                /*
                According to the spec, "The <Assertion> element(s) in the <Response> MUST be signed". Therefore we
                should not reply on any property to decide this behaviour. Hence the property is set to sign by default.
                */
                providerDTO.setDoSignAssertions(true);
                providerDTO.setDoSingleLogout(providerDO.isDoSingleLogout());
                providerDTO.setDoFrontChannelLogout(providerDO.isDoFrontChannelLogout());
                providerDTO.setFrontChannelLogoutBinding(providerDO.getFrontChannelLogoutBinding());
                providerDTO.setAssertionQueryRequestProfileEnabled(providerDO.isAssertionQueryRequestProfileEnabled());
                providerDTO.setSupportedAssertionQueryRequestTypes(providerDO.getSupportedAssertionQueryRequestTypes());
                providerDTO.setEnableSAML2ArtifactBinding(providerDO.isEnableSAML2ArtifactBinding());
                providerDTO.setDoValidateSignatureInArtifactResolve(
                        providerDO.isDoValidateSignatureInArtifactResolve());

                if (providerDO.getLoginPageURL() == null || "null".equals(providerDO.getLoginPageURL())) {
                    providerDTO.setLoginPageURL("");
                } else {
                    providerDTO.setLoginPageURL(providerDO.getLoginPageURL());
                }

                providerDTO.setSloResponseURL(providerDO.getSloResponseURL());
                providerDTO.setSloRequestURL(providerDO.getSloRequestURL());
                providerDTO.setRequestedClaims(providerDO.getRequestedClaims());
                providerDTO.setRequestedAudiences(providerDO.getRequestedAudiences());
                providerDTO.setRequestedRecipients(providerDO.getRequestedRecipients());
                providerDTO.setEnableAttributesByDefault(providerDO.isEnableAttributesByDefault());
                providerDTO.setNameIdClaimUri(providerDO.getNameIdClaimUri());
                providerDTO.setNameIDFormat(providerDO.getNameIDFormat());

                if (providerDTO.getNameIDFormat() == null) {
                    providerDTO.setNameIDFormat(NameIdentifier.EMAIL);
                }
                providerDTO.setNameIDFormat(providerDTO.getNameIDFormat().replace(":", "/"));

                providerDTO.setIdPInitSSOEnabled(providerDO.isIdPInitSSOEnabled());
                providerDTO.setIdPInitSLOEnabled(providerDO.isIdPInitSLOEnabled());
                providerDTO.setIdpInitSLOReturnToURLs(providerDO.getIdpInitSLOReturnToURLs());
                providerDTO.setDoEnableEncryptedAssertion(providerDO.isDoEnableEncryptedAssertion());
                providerDTO.setDoValidateSignatureInRequests(providerDO.isDoValidateSignatureInRequests());
                providerDTO.setIdpEntityIDAlias(providerDO.getIdpEntityIDAlias());
                serviceProviders[i] = providerDTO;
            }
        } catch (IdentityException e) {
            String message = "Error obtaining a registry instance for reading service provider list";
            throw new IdentityException(message, e);
        }

        SAMLSSOServiceProviderInfoDTO serviceProviderInfoDTO = new SAMLSSOServiceProviderInfoDTO();
        serviceProviderInfoDTO.setServiceProviders(serviceProviders);

        //if it is tenant zero
        if (registry.getTenantId() == 0) {
            serviceProviderInfoDTO.setTenantZero(true);
        }
        return serviceProviderInfoDTO;
    }

    public SAMLSSOServiceProviderInfoDTO getServiceProviders() throws IdentityException {
        SAMLSSOServiceProviderDTO[] serviceProviders = null;
        JDBCSAMLSSOAppDAO jdbcsamlssoAppDAO = new JDBCSAMLSSOAppDAO();
        ArrayList<SAMLSSO_Model> list = jdbcsamlssoAppDAO.getAllServiceProviders();
        HashMap<String,SAMLSSOServiceProviderDTO> map = new HashMap<>();
        for(SAMLSSO_Model item: list){
            if(map.containsKey(item.getIssuer_name())){
                SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = map.get(item.getIssuer_name());
                samlssoServiceProviderDTO.setDoSignAssertions(true);
                map.put(item.getIssuer_name(), updateServiceProviderDTO(samlssoServiceProviderDTO,item));
            }
            else {
                SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
                map.put(item.getIssuer_name(), updateServiceProviderDTO(samlssoServiceProviderDTO,item));
            }
        }
        serviceProviders = map.values().toArray(new SAMLSSOServiceProviderDTO[0]);

        SAMLSSOServiceProviderInfoDTO serviceProviderInfoDTO = new SAMLSSOServiceProviderInfoDTO();
        serviceProviderInfoDTO.setServiceProviders(serviceProviders);

        //if it is tenant zero
        if (registry.getTenantId() == 0) {
            serviceProviderInfoDTO.setTenantZero(true);
        }
        return serviceProviderInfoDTO;
    }

    /**
     * Remove an existing service provider.
     *
     * @param issuer issuer name
     * @return true is successful
     * @throws IdentityException
     */
    public boolean removeServiceProvider(String issuer) throws IdentityException {
        try {
//            IdentityPersistenceManager persistenceManager = IdentityPersistenceManager.getPersistanceManager();
            JDBCSAMLSSOAppDAO jdbcsamlssoAppDAO = new JDBCSAMLSSOAppDAO();
            jdbcsamlssoAppDAO.removeServiceProvider(issuer);
//            return persistenceManager.removeServiceProvider(registry, issuer);
            return true;
        } catch (ArtifactBindingException e) {
            throw new RuntimeException(e);
        }
    }

    protected String getTenantDomain() {

        return CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    }

    public List<SAMLSSO_Model> convertServiceProviderToList(SAMLSSOServiceProviderDTO serviceProviderDTO) {
        List<SAMLSSO_Model> list = new ArrayList<>();
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"issuer",serviceProviderDTO.getIssuer(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"issuerQualifier",serviceProviderDTO.getIssuerQualifier(),registry.getTenantId()));
        for(String url : serviceProviderDTO.getAssertionConsumerUrls()){
            list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"assertionConsumerUrls",url,registry.getTenantId()));
        }
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"defaultAssertionConsumerUrl",serviceProviderDTO.getDefaultAssertionConsumerUrl(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"signingAlgorithmURI",serviceProviderDTO.getSigningAlgorithmURI(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"digestAlgorithmURI",serviceProviderDTO.getDigestAlgorithmURI(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"assertionEncryptionAlgorithmURI",serviceProviderDTO.getAssertionEncryptionAlgorithmURI(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"keyEncryptionAlgorithmURI",serviceProviderDTO.getKeyEncryptionAlgorithmURI(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"certAlias",serviceProviderDTO.getCertAlias(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"attributeConsumingServiceIndex",serviceProviderDTO.getAttributeConsumingServiceIndex(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"doSignResponse",serviceProviderDTO.isDoSignResponse() ? "true":"false",registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"doSingleLogout",serviceProviderDTO.isDoSingleLogout() ? "true":"false",registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"doFrontChannelLogout",serviceProviderDTO.isDoFrontChannelLogout() ? "true":"false",registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"frontChannelLogoutBinding",serviceProviderDTO.getFrontChannelLogoutBinding(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"isAssertionQueryRequestProfileEnabled",serviceProviderDTO.isAssertionQueryRequestProfileEnabled() ? "true":"false",registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"supportedAssertionQueryRequestTypes",serviceProviderDTO.getSupportedAssertionQueryRequestTypes(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"enableSAML2ArtifactBinding",serviceProviderDTO.isEnableSAML2ArtifactBinding() ? "true":"false",registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"doValidateSignatureInArtifactResolve",serviceProviderDTO.isDoValidateSignatureInArtifactResolve() ? "true":"false",registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"loginPageURL",serviceProviderDTO.getLoginPageURL(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"sloResponseURL",serviceProviderDTO.getSloResponseURL(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"sloRequestURL",serviceProviderDTO.getSloRequestURL(),registry.getTenantId()));
        for(String claim : serviceProviderDTO.getRequestedClaims()){
            list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"requestedClaims",claim,registry.getTenantId()));
        }
        for(String audience : serviceProviderDTO.getRequestedAudiences()){
            list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"requestedAudiences",audience,registry.getTenantId()));
        }
        for(String recipient : serviceProviderDTO.getRequestedRecipients()){
            list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"requestedRecipients",recipient,registry.getTenantId()));
        }
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"enableAttributesByDefault",serviceProviderDTO.isEnableAttributesByDefault() ? "true":"false",registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"nameIdClaimUri",serviceProviderDTO.getNameIdClaimUri(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"nameIDFormat",serviceProviderDTO.getNameIDFormat(),registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"idPInitSSOEnabled",serviceProviderDTO.isIdPInitSSOEnabled()?"true":"false",registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"idPInitSLOEnabled",serviceProviderDTO.isIdPInitSLOEnabled()?"true":"false",registry.getTenantId()));
        for(String url : serviceProviderDTO.getIdpInitSLOReturnToURLs()){
            list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"idpInitSLOReturnToURLs",url,registry.getTenantId()));
        }
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"doEnableEncryptedAssertion",serviceProviderDTO.isDoEnableEncryptedAssertion()?"true":"false",registry.getTenantId()));
        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"doValidateSignatureInRequests",serviceProviderDTO.isDoValidateSignatureInRequests()?"true":"false",registry.getTenantId()));

        list.add(new SAMLSSO_Model(serviceProviderDTO.getIssuer(),"idpEntityIDAlias",serviceProviderDTO.getIdpEntityIDAlias(),registry.getTenantId()));


        return list;
    }

    private SAMLSSOServiceProviderDTO updateServiceProviderDTO(SAMLSSOServiceProviderDTO samlssoServiceProviderDTO, SAMLSSO_Model item) {
        switch (item.getKey_name()){
            case "issuer":
                samlssoServiceProviderDTO.setIssuer(item.getValue_name());
                break;
            case "issuerQualifier":
                samlssoServiceProviderDTO.setIssuerQualifier(item.getValue_name());
                break;
            case "assertionConsumerUrls":
                String[] arr = samlssoServiceProviderDTO.getAssertionConsumerUrls();
                ArrayList<String> list = (ArrayList<String>) Arrays.asList(arr);
                list.add(item.getValue_name());
                samlssoServiceProviderDTO.setAssertionConsumerUrls(list.toArray(new String[0]));
                break;
            case "defaultAssertionConsumerUrl":
                samlssoServiceProviderDTO.setDefaultAssertionConsumerUrl(item.getValue_name());
                break;
            case "signingAlgorithmURI":
                samlssoServiceProviderDTO.setSigningAlgorithmURI(item.getValue_name());
                break;
            case "digestAlgorithmURI":
                samlssoServiceProviderDTO.setDigestAlgorithmURI(item.getValue_name());
                break;
            case "assertionEncryptionAlgorithmURI":
                samlssoServiceProviderDTO.setAssertionEncryptionAlgorithmURI(item.getValue_name());
                break;
            case "keyEncryptionAlgorithmURI":
                samlssoServiceProviderDTO.setKeyEncryptionAlgorithmURI(item.getValue_name());
                break;
            case "certAlias":
                samlssoServiceProviderDTO.setCertAlias(item.getValue_name());
                break;
            case "attributeConsumingServiceIndex":
                samlssoServiceProviderDTO.setAttributeConsumingServiceIndex(item.getValue_name());
                if (StringUtils.isNotBlank(item.getValue_name())) {
                    samlssoServiceProviderDTO.setEnableAttributeProfile(true);
                }
                break;
            case "doSignResponse":
                samlssoServiceProviderDTO.setDoSignResponse(item.getValue_name().equals("true"));
                break;
            case "doSingleLogout":
                samlssoServiceProviderDTO.setDoSingleLogout(item.getValue_name().equals("true"));
                break;
            case "doFrontChannelLogout":
                samlssoServiceProviderDTO.setDoFrontChannelLogout(item.getValue_name().equals("true"));
                break;
            case "frontChannelLogoutBinding":
                samlssoServiceProviderDTO.setFrontChannelLogoutBinding(item.getValue_name());
                break;
            case "isAssertionQueryRequestProfileEnabled":
                samlssoServiceProviderDTO.setAssertionQueryRequestProfileEnabled(item.getValue_name().equals("true"));
                break;
            case "supportedAssertionQueryRequestTypes":
                samlssoServiceProviderDTO.setSupportedAssertionQueryRequestTypes(item.getValue_name());
                break;
            case "enableSAML2ArtifactBinding":
                samlssoServiceProviderDTO.setEnableSAML2ArtifactBinding(item.getValue_name().equals("true"));
                break;
            case "doValidateSignatureInArtifactResolve":
                samlssoServiceProviderDTO.setDoValidateSignatureInArtifactResolve(item.getValue_name().equals("true"));
                break;
            case "loginPageURL":
                if(item.getValue_name() == null || item.getValue_name().equals("null")){
                    samlssoServiceProviderDTO.setLoginPageURL("");
                }
                else{
                    samlssoServiceProviderDTO.setLoginPageURL(item.getValue_name());
                }
                break;
            case "sloResponseURL":
                samlssoServiceProviderDTO.setSloResponseURL(item.getValue_name());
                break;
            case "sloRequestURL":
                samlssoServiceProviderDTO.setSloRequestURL(item.getValue_name());
                break;
            case "requestedClaims":
                String[] requestedClaimsArray = samlssoServiceProviderDTO.getRequestedClaims();
                ArrayList<String> requestedClaimsList = (ArrayList<String>) Arrays.asList(requestedClaimsArray);
                requestedClaimsList.add(item.getValue_name());
                samlssoServiceProviderDTO.setAssertionConsumerUrls(requestedClaimsList.toArray(new String[0]));
                break;
            case "requestedAudiences":
                String[] requestedAudiencesArray = samlssoServiceProviderDTO.getRequestedAudiences();
                ArrayList<String> requestedAudiencesList = (ArrayList<String>) Arrays.asList(requestedAudiencesArray);
                requestedAudiencesList.add(item.getValue_name());
                samlssoServiceProviderDTO.setAssertionConsumerUrls(requestedAudiencesList.toArray(new String[0]));
                break;
            case "requestedRecipients":
                String[] requestedRecipientsArray = samlssoServiceProviderDTO.getRequestedRecipients();
                ArrayList<String> requestedRecipientsList = (ArrayList<String>) Arrays.asList(requestedRecipientsArray);
                requestedRecipientsList.add(item.getValue_name());
                samlssoServiceProviderDTO.setAssertionConsumerUrls(requestedRecipientsList.toArray(new String[0]));
                break;
            case "enableAttributesByDefault":
                samlssoServiceProviderDTO.setEnableAttributesByDefault(item.getValue_name().equals("true"));
                break;
            case "nameIdClaimUri":
                samlssoServiceProviderDTO.setNameIdClaimUri(item.getValue_name());
                break;
            case "nameIDFormat":
                samlssoServiceProviderDTO.setNameIDFormat(item.getValue_name());
                if (samlssoServiceProviderDTO.getNameIDFormat() == null) {
                    samlssoServiceProviderDTO.setNameIDFormat(NameIdentifier.EMAIL);
                }
                samlssoServiceProviderDTO.setNameIDFormat(samlssoServiceProviderDTO.getNameIDFormat().replace(":", "/"));
                break;
            case "idPInitSSOEnabled":
                samlssoServiceProviderDTO.setIdPInitSSOEnabled(item.getValue_name().equals("true"));
                break;
            case "idPInitSLOEnabled":
                samlssoServiceProviderDTO.setIdPInitSLOEnabled(item.getValue_name().equals("true"));
                break;
            case "idpInitSLOReturnToURLs":
                String[] idpInitSLOReturnToURLsArray = samlssoServiceProviderDTO.getIdpInitSLOReturnToURLs();
                ArrayList<String> idpInitSLOReturnToURLsList = (ArrayList<String>) Arrays.asList(idpInitSLOReturnToURLsArray);
                idpInitSLOReturnToURLsList.add(item.getValue_name());
                samlssoServiceProviderDTO.setAssertionConsumerUrls(idpInitSLOReturnToURLsList.toArray(new String[0]));
                break;
            case "doEnableEncryptedAssertion":
                samlssoServiceProviderDTO.setDoEnableEncryptedAssertion(item.getValue_name().equals("true"));
                break;
            case "doValidateSignatureInRequests":
                samlssoServiceProviderDTO.setDoValidateSignatureInRequests(item.getValue_name().equals("true"));
                break;
            case "idpEntityIDAlias":
                samlssoServiceProviderDTO.setIdpEntityIDAlias(item.getValue_name());
                break;
        }
        return samlssoServiceProviderDTO;
    }

}
