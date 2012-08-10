package com.mulesoft.module.indivo;

import java.util.Map;

import oauth.signpost.OAuth;
import oauth.signpost.OAuthConsumer;
import oauth.signpost.commonshttp.CommonsHttpOAuthProvider;
import oauth.signpost.commonshttp.HttpRequestAdapter;
import oauth.signpost.exception.OAuthCommunicationException;
import oauth.signpost.exception.OAuthExpectationFailedException;
import oauth.signpost.exception.OAuthMessageSignerException;
import oauth.signpost.exception.OAuthNotAuthorizedException;
import oauth.signpost.http.HttpParameters;
import oauth.signpost.http.HttpRequest;
import oauth.signpost.http.HttpResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;

public class IndivoOAuthProvider extends CommonsHttpOAuthProvider {

    /**
     * 
     */
    private static final long serialVersionUID = 4698666141002845460L;
    protected static final Log logger = LogFactory.getLog(IndivoOAuthProvider.class);
    
    public IndivoOAuthProvider(String requestTokenEndpointUrl,
            String accessTokenEndpointUrl, String authorizationWebsiteUrl) {
        super(requestTokenEndpointUrl, accessTokenEndpointUrl, authorizationWebsiteUrl);
        // TODO Auto-generated constructor stub
    }

    protected void retrieveToken(OAuthConsumer consumer, String endpointUrl,
            HttpParameters customOAuthParams) throws OAuthMessageSignerException,
            OAuthCommunicationException, OAuthNotAuthorizedException,
            OAuthExpectationFailedException {
        Map<String, String> defaultHeaders = getRequestHeaders();

        if (consumer.getConsumerKey() == null || consumer.getConsumerSecret() == null) {
            throw new OAuthExpectationFailedException("Consumer key or secret not set");
        }

        HttpRequest request = null;
        HttpResponse response = null;
        try {
            request = createRequest(endpointUrl, customOAuthParams);
            for (String header : defaultHeaders.keySet()) {
                request.setHeader(header, defaultHeaders.get(header));
            }
            
            if (customOAuthParams != null && !customOAuthParams.isEmpty()) {
                consumer.setAdditionalParameters(customOAuthParams);
            }
            
//            if (this.listener != null) {
//                this.listener.prepareRequest(request);
//            }
            
            consumer.sign(request);
            
//            if (this.listener != null) {
//                this.listener.prepareSubmission(request);
//            }

            response = sendRequest(request);
            int statusCode = response.getStatusCode();

//            boolean requestHandled = false;
//            if (this.listener != null) {
//                requestHandled = this.listener.onResponseReceived(request, response);
//            }
//            if (requestHandled) {
//                return;
//            }

            if (statusCode >= 300) {
                handleUnexpectedResponse(statusCode, response);
            }

            HttpParameters responseParams = OAuth.decodeForm(response.getContent());

            String token = responseParams.getFirst(OAuth.OAUTH_TOKEN);
            String secret = responseParams.getFirst(OAuth.OAUTH_TOKEN_SECRET);
            responseParams.remove(OAuth.OAUTH_TOKEN);
            responseParams.remove(OAuth.OAUTH_TOKEN_SECRET);

            logger.debug("TOKEN IS:  " + token);
            logger.debug("SECRET IS:  " + secret);
            
            setResponseParameters(responseParams);

            if (token == null || secret == null) {
                throw new OAuthExpectationFailedException(
                        "Request token or token secret not set in server reply. "
                                + "The service provider you use is probably buggy.");
            }

            consumer.setTokenWithSecret(token, secret);

        } catch (OAuthNotAuthorizedException e) {
            throw e;
        } catch (OAuthExpectationFailedException e) {
            throw e;
        } catch (Exception e) {
            throw new OAuthCommunicationException(e);
        } finally {
            try {
                closeConnection(request, response);
            } catch (Exception e) {
                throw new OAuthCommunicationException(e);
            }
        }
    }
    
    protected HttpRequest createRequest(String endpointUrl, HttpParameters customOAuthParams) throws Exception {
        HttpPost request = new HttpPost(endpointUrl);
        
        StringBuffer buffer = new StringBuffer();
        
        for (String key : customOAuthParams.keySet()) {
            String value = customOAuthParams.getFirst(key);
            logger.debug("Adding form param: key: " + key + " value: " + value);
            request.setHeader(key, value);
            buffer.append(key).append("=").append(value).append("&");
        }
        
        StringEntity body = new StringEntity(buffer.toString());
        body.setContentType("application/x-www-form-urlencoded");
        request.setEntity(body);
        return new HttpRequestAdapter(request);
    }
}
