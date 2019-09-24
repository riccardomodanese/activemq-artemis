package org.apache.activemq.artemis.core.remoting.impl.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.jboss.logging.Logger;

/**
 * Basic custom X509 Trust Manager.
 * It works as a proxy through another {@link TrustManager}
 *
 */
public class CustomX509TrustManager implements X509TrustManager {

   private static final Logger logger = Logger.getLogger(SSLSupport.class);

   private KeyStore trustStore;
   private X509TrustManager trustManager;
   private TrustManagerFactory trustManagerFactory;

   public CustomX509TrustManager(TrustManagerFactory trustManagerFactory) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
      logger.infov("Custom X509 trust manager... init");
      trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
      //just demo. These parameters, if needed, should be kept from configuration (may be acceptor/connector configurations?)
      String truststoreFileName = "/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.222.b10-0.el7_6.x86_64/jre/lib/security/cacerts";
      String trustStorePassword = "changeit";
      // initialize keystore
      try (FileInputStream fis = new FileInputStream(new File(truststoreFileName))) {
         trustStore.load(fis, trustStorePassword.toCharArray());
         logger.infov("Custom X509 trust manager... load truststore file done ({0})", new Object[] {truststoreFileName});
      }
      this.trustManagerFactory = trustManagerFactory;
      this.trustManagerFactory.init(trustStore);
      TrustManager[] trustMngrs = this.trustManagerFactory.getTrustManagers();
      for (TrustManager tm : trustMngrs) {
         if ((tm instanceof X509TrustManager)) {
            logger.infov("Custom X509 trust manager... found X509 trust manager");
            trustManager = (X509TrustManager) tm;
            break;
         }
      }
      logger.infov("Custom X509 trust manager... init DONE ({0})", new Object[] {trustManager});
   }

   @Override
   public void checkClientTrusted(X509Certificate[] x509Certificates, String authType) throws CertificateException {
      logger.infov("##### Checking client... Checking validity");
      trustManager.checkClientTrusted(x509Certificates, authType);
   }

   @Override
   public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
      logger.infov("##### checking server certificate");
      trustManager.checkServerTrusted(x509Certificates, s);
   }

   @Override
   public X509Certificate[] getAcceptedIssuers() {
      logger.infov("##### returning accepted issuers");
      if (logger.isDebugEnabled()) {
         if (trustManager.getAcceptedIssuers() == null) {
            logger.debugv("accepted issuers null");
         } else if (trustManager.getAcceptedIssuers().length == 0) {
            logger.debugv("accepted issuers empty");
         } else {
            logger.debugv("Found {0} accepted issuers: ", new Object[] {trustManager.getAcceptedIssuers().length});
         }
      }
      logger.infov("Accepted issuers: {0}", new Object[] {trustManager.getAcceptedIssuers().length});
      return trustManager.getAcceptedIssuers();
   }

}
