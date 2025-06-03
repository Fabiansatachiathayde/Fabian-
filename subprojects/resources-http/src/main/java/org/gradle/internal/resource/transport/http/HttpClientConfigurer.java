/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.gradle.internal.resource.transport.http;

import org.apache.http.client.CredentialsProvider;
import org.apache.http.config.SocketConfig;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.SystemDefaultCredentialsProvider;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import org.gradle.authentication.Authentication;
import org.gradle.internal.resource.UriTextResource;

import javax.net.ssl.HostnameVerifier;
import java.net.ProxySelector;
import java.util.Collection;

public class HttpClientConfigurer {

    private final HttpSettings httpSettings;

    public HttpClientConfigurer(HttpSettings httpSettings) {
        this.httpSettings = httpSettings;
    }

    public void configure(HttpClientBuilder builder) {
        SystemDefaultCredentialsProvider credentialsProvider = new SystemDefaultCredentialsProvider();
        configureSslSocketConnectionFactory(builder, httpSettings.getSslContextFactory(), httpSettings.getHostnameVerifier());
        configureAuthSchemeRegistry(builder);
        configureCredentials(builder, credentialsProvider, httpSettings.getAuthenticationSettings());
        configureProxy(builder, credentialsProvider, httpSettings);
        configureUserAgent(builder);
        configureCookieSpecRegistry(builder);
        configureRequestConfig(builder);
        configureSocketConfig(builder);
        configureRedirectStrategy(builder);
        builder.setDefaultCredentialsProvider(credentialsProvider);
        builder.setMaxConnTotal(HttpClientUtil.MAX_HTTP_CONNECTIONS);
        builder.setMaxConnPerRoute(HttpClientUtil.MAX_HTTP_CONNECTIONS);
    }

    private void configureSslSocketConnectionFactory(HttpClientBuilder builder, SslContextFactory sslContextFactory, HostnameVerifier hostnameVerifier) {
        builder.setSSLSocketFactory(new SSLConnectionSocketFactory(sslContextFactory.createSslContext(), HttpClientUtil.supportedTlsVersions().toArray(new String[]{}), null, hostnameVerifier));
    }

    private void configureAuthSchemeRegistry(HttpClientBuilder builder) {
        builder.setDefaultAuthSchemeRegistry(HttpClientUtil.createAuthSchemeRegistry());
    }

    private void configureCredentials(HttpClientBuilder builder, CredentialsProvider credentialsProvider, Collection<Authentication> authentications) {
        if (authentications.size() > 0) {
            HttpClientUtil.useCredentials(credentialsProvider, authentications);

            // Use preemptive authorisation if no other authorisation has been established

            builder.addInterceptorFirst(HttpClientUtil.createPreemptiveAuthInterceptor(authentications));
        }
    }

    private void configureProxy(HttpClientBuilder builder, CredentialsProvider credentialsProvider, HttpSettings httpSettings) {
        HttpClientUtil.configureProxy(credentialsProvider, httpSettings);
        builder.setRoutePlanner(new SystemDefaultRoutePlanner(ProxySelector.getDefault()));
    }

    public void configureUserAgent(HttpClientBuilder builder) {
        builder.setUserAgent(UriTextResource.getUserAgentString());
    }

    private void configureCookieSpecRegistry(HttpClientBuilder builder) {
        HttpClientUtil.CookieConfig config = HttpClientUtil.createCookieConfig();
        builder.setPublicSuffixMatcher(config.publicSuffixMatcher);
        builder.setDefaultCookieSpecRegistry(config.cookieSpecRegistry);
    }

    private void configureRequestConfig(HttpClientBuilder builder) {
        builder.setDefaultRequestConfig(HttpClientUtil.createDefaultRequestConfig(httpSettings));
    }

    private void configureSocketConfig(HttpClientBuilder builder) {
        HttpTimeoutSettings timeoutSettings = httpSettings.getTimeoutSettings();
        builder.setDefaultSocketConfig(SocketConfig.custom().setSoTimeout(timeoutSettings.getSocketTimeoutMs()).setSoKeepAlive(true).build());
    }

    private void configureRedirectStrategy(HttpClientBuilder builder) {
        builder.setRedirectStrategy(HttpClientUtil.createRedirectStrategy(httpSettings));
    }

}
