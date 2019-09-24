package org.apache.activemq.artemis.core.remoting.impl.ssl;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.cert.CertificateException;

import javax.net.ssl.TrustManagerFactory;

public class CustomTrustManagerFactory extends TrustManagerFactory {

   private static final String CUSTOM_PROVIDER_NAME = "custom provider name";
   private static final String CUSTOM_PROVIDER_INFO = "";

   private static final Provider PROVIDER = new Provider(CUSTOM_PROVIDER_NAME, 1.0, CUSTOM_PROVIDER_INFO) {
      private static final long serialVersionUID = 6452172716597104806L;
   };

   public CustomTrustManagerFactory() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
      super(new CustomTrustManagerFactorySpi(), PROVIDER, TrustManagerFactory.getDefaultAlgorithm());
   }

}
