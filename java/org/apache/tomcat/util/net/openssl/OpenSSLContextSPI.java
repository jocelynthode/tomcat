/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.net.openssl;


import org.apache.tomcat.jni.*;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.*;
import org.apache.tomcat.jni.SSLContext;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class OpenSSLContextSPI extends SSLContextSpi {

    private static final Logger LOG = Logger.getLogger(OpenSSLContextSPI.class.getName());

    public static final int DEFAULT_SESSION_CACHE_SIZE = 1000;

    private static final String BEGIN_CERT = "-----BEGIN RSA PRIVATE KEY-----\n";

    private static final String END_CERT = "\n-----END RSA PRIVATE KEY-----";

    private static final String[] ALGORITHMS = {"RSA"};

    private static final String defaultProtocol = "TLS";

    private static volatile boolean sslInitialized;

    private List<String> ciphers = new ArrayList<>();

    public List<String> getCiphers() {
        return ciphers;
    }

    private String enabledProtocol;

    public String getEnabledProtocol() {
        return enabledProtocol;
    }

    public void setEnabledProtocol(String protocol) {
        enabledProtocol = (protocol == null) ? defaultProtocol : protocol;
    }

    protected final long ctx;

    static final CertificateFactory X509_CERT_FACTORY;
    private boolean initialized = false;

    static {
        try {
            X509_CERT_FACTORY = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    OpenSSLContextSPI(final int value) throws SSLException {
        try {
            initializeSSL();
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            // Create SSL Context
            try {
                ctx = SSLContext.make(value, SSL.SSL_MODE_SERVER);
            } catch (Exception e) {
                // If the sslEngine is disabled on the AprLifecycleListener
                // there will be an Exception here but there is no way to check
                // the AprLifecycleListener settings from here
                throw new SSLException("Failed to make SSL context", e);
            }
            try {
                //disable unsafe renegotiation
                SSLContext.clearOptions(ctx, SSL.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
            } catch (UnsatisfiedLinkError e) {
                // Ignore
            }

            // Disable compression
            boolean disableCompressionSupported = false;
            try {
                disableCompressionSupported = SSL.hasOp(SSL.SSL_OP_NO_COMPRESSION);
                if (disableCompressionSupported) {
                    SSLContext.setOptions(ctx, SSL.SSL_OP_NO_COMPRESSION);
                }
            } catch (UnsatisfiedLinkError e) {
                // Ignore
            }
            if (!disableCompressionSupported) {
                LOG.fine("The version of SSL in use does not support disabling compression");
            }

            // Disable TLS Session Tickets (RFC4507) to protect perfect forward secrecy
            boolean disableSessionTicketsSupported = false;
            try {
                disableSessionTicketsSupported = SSL.hasOp(SSL.SSL_OP_NO_TICKET);
                if (disableSessionTicketsSupported) {
                    SSLContext.setOptions(ctx, SSL.SSL_OP_NO_TICKET);
                }
            } catch (UnsatisfiedLinkError e) {
                // Ignore
            }
            if (!disableSessionTicketsSupported) {
                // OpenSSL is too old to support TLS Session Tickets.
                LOG.fine("The version of SSL in use does not support disabling session tickets");
            }
        } catch (Exception e) {
            throw new RuntimeException( "Failed to initialise OpenSSL context", e);
        }

    }

    /**
     * Setup the SSL_CTX
     *
     * @param kms Must contain a KeyManager of the type
     *            {@code OpenSSLKeyManager}
     * @param tms
     */
    private synchronized void init(KeyManager[] kms, TrustManager[] tms) throws KeyManagementException {
        if (initialized) {
            LOG.warning("Ignoring second invocation of init() method");
            return;
        }

        try {
            // Load Server key and certificate
            X509KeyManager keyManager = chooseKeyManager(kms);
            if (keyManager == null) {
                throw new IllegalArgumentException("could not find suitable trust manager");
            }
            boolean oneFound = false;
            for (String algorithm : ALGORITHMS) {

                final String[] aliases = keyManager.getServerAliases(algorithm, null);
                if (aliases != null && aliases.length != 0) {
                    oneFound = true;
                    String alias = aliases[0];
                    if(LOG.isLoggable(Level.FINE)) {
                        LOG.fine("Using alias " + alias);
                    }

                    X509Certificate certificate = keyManager.getCertificateChain(alias)[0];
                    PrivateKey key = keyManager.getPrivateKey(alias);
                    StringBuilder sb = new StringBuilder(BEGIN_CERT);
                    sb.append(Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded()));
                    sb.append(END_CERT);
                    SSLContext.setCertificateRaw(ctx, certificate.getEncoded(), sb.toString().getBytes(StandardCharsets.US_ASCII), algorithm.equals("RSA") ? SSL.SSL_AIDX_RSA : SSL.SSL_AIDX_DSA);
                }
            }

            if (!oneFound) {
                throw new IllegalStateException("KeyManager does not contain a valid certificates");
            }
            /*
            // Support Client Certificates
            SSL.setCACertificate(ctx,
                    SSLHostConfig.adjustRelativePath(sslHostConfig.getCaCertificateFile()),
                    SSLHostConfig.adjustRelativePath(sslHostConfig.getCaCertificatePath()));
            // Set revocation
            SSL.setCARevocation(ctx,
                    SSLHostConfig.adjustRelativePath(
                            sslHostConfig.getCertificateRevocationListFile()),
                    SSLHostConfig.adjustRelativePath(
                            sslHostConfig.getCertificateRevocationListPath()));
            */
            // Client certificate verification

            SSLContext.setSessionCacheSize(ctx, DEFAULT_SESSION_CACHE_SIZE);

            if (tms != null) {
                final X509TrustManager manager = chooseTrustManager(tms);
                SSLContext.setCertVerifyCallback(ctx, new CertificateVerifier() {
                    @Override
                    public boolean verify(long ssl, byte[][] chain, String auth) {
                        X509Certificate[] peerCerts = certificates(chain);
                        try {
                            manager.checkClientTrusted(peerCerts, auth);
                            return true;
                        } catch (Exception e) {
                            if(LOG.isLoggable(Level.FINE)) {
                                LOG.log(Level.FINE, "Certificate verification failed", e);
                            }
                        }
                        return false;
                    }
                });
            }
            String[] protos = new OpenSSLProtocols(enabledProtocol).getProtocols();

//            sessionContext = new OpenSSLServerSessionContext(ctx);
//            sessionContext.setSessionIdContext("test".getBytes(StandardCharsets.US_ASCII));
            initialized = true;

            //TODO: ALPN must be optional
//            SSL.enableAlpn(ctx);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private X509KeyManager chooseKeyManager(KeyManager[] tms) {
        for (KeyManager tm : tms) {
            if (tm instanceof X509KeyManager) {
                return (X509KeyManager) tm;
            }
        }
        throw new IllegalStateException("Key manager is missing");
    }

    static X509TrustManager chooseTrustManager(TrustManager[] managers) {
        for (TrustManager m : managers) {
            if (m instanceof X509TrustManager) {
                return (X509TrustManager) m;
            }
        }
        throw new IllegalStateException("Trust manager is missing");
    }

    private static X509Certificate[] certificates(byte[][] chain) {
        X509Certificate[] peerCerts = new X509Certificate[chain.length];
        for (int i = 0; i < peerCerts.length; i++) {
            peerCerts[i] = new OpenSslX509Certificate(chain[i]);
        }
        return peerCerts;
    }

//    public SSLSessionContext getServerSessionContext() {
//        return sessionContext;
//    }

    public SSLEngine createSSLEngine() {
        return new OpenSSLEngine(ctx, defaultProtocol, false, null, false);
    }

    public SSLServerSocketFactory getServerSocketFactory() {
        throw new UnsupportedOperationException();
    }

    public SSLParameters getSupportedSSLParameters() {
        throw new UnsupportedOperationException();
    }

    /**
     * Generates a key specification for an (encrypted) private key.
     *
     * @param password characters, if {@code null} or empty an unencrypted key
     *                 is assumed
     * @param key      bytes of the DER encoded private key
     * @return a key specification
     * @throws IOException                        if parsing {@code key} fails
     * @throws NoSuchAlgorithmException           if the algorithm used to encrypt
     *                                            {@code key} is unknown
     * @throws NoSuchPaddingException             if the padding scheme specified in the
     *                                            decryption algorithm is unknown
     * @throws InvalidKeySpecException            if the decryption key based on
     *                                            {@code password} cannot be generated
     * @throws InvalidKeyException                if the decryption key based on
     *                                            {@code password} cannot be used to decrypt {@code key}
     * @throws InvalidAlgorithmParameterException if decryption algorithm
     *                                            parameters are somehow faulty
     */
    protected static PKCS8EncodedKeySpec generateKeySpec(char[] password, byte[] key)
            throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException,
            InvalidKeyException, InvalidAlgorithmParameterException {

        if (password == null || password.length == 0) {
            return new PKCS8EncodedKeySpec(key);
        }

        EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
        SecretKey pbeKey = keyFactory.generateSecret(pbeKeySpec);

        Cipher cipher = Cipher.getInstance(encryptedPrivateKeyInfo.getAlgName());
        cipher.init(Cipher.DECRYPT_MODE, pbeKey, encryptedPrivateKeyInfo.getAlgParameters());

        return encryptedPrivateKeyInfo.getKeySpec(cipher);
    }

    @Override
    protected final void finalize() throws Throwable {
        super.finalize();
        synchronized (OpenSSLContextSPI.class) {
            if (ctx != 0) {
                SSLContext.free(ctx);
            }
        }
    }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) throws KeyManagementException {
        init(km, tm);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        throw new UnsupportedOperationException("method not supported");
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        throw new UnsupportedOperationException("method not supported");
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return createSSLEngine();
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        return createSSLEngine();
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
//        return sessionContext;
        return null;
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
//        return sessionContext;
        return null;
    }



//    public void sessionRemoved(byte[] session) {
//        sessionContext.remove(session);
//    }

    public static final class OpenSSLTLS_1_0_ContextSpi extends OpenSSLContextSPI {

        public OpenSSLTLS_1_0_ContextSpi() throws SSLException {
            super(SSL.SSL_PROTOCOL_TLSV1);
        }
    }

    public static final class OpenSSLTLS_1_1_ContextSpi extends OpenSSLContextSPI {

        public OpenSSLTLS_1_1_ContextSpi() throws SSLException {
            super(SSL.SSL_PROTOCOL_TLSV1_1);
        }
    }

    public static final class OpenSSLTLS_1_2_ContextSpi extends OpenSSLContextSPI {

        public OpenSSLTLS_1_2_ContextSpi() throws SSLException {
            super(SSL.SSL_PROTOCOL_TLSV1_2);
        }
    }

    public static void initializeSSL() throws Exception {
        if (sslInitialized) {
            //only once per VM
            return;
        }

        sslInitialized = true;
        String sslEngine = "on";  // TODO: class field

        // Load shared object
        Library.initialize(null);

        // Initialize OpenSSL
        String methodName = "initialize";
        Class<?> paramTypes[] = {String.class};
        Object[] paramValues = new Object[1];
        paramValues[0] = "on".equalsIgnoreCase(sslEngine) ? null : sslEngine;
        Class<?> clazz = Class.forName("org.apache.tomcat.jni.SSL");
        Method method = clazz.getMethod(methodName, paramTypes);
        method.invoke(null, paramValues);
    }
}
