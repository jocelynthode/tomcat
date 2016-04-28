package org.apache.tomcat.util.net.openssl;

/**
 * @author Stuart Douglas
 */
interface ServerALPNCallback {

    String select(String[] protocols);
}
