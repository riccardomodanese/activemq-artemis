package org.apache.activemq.artemis.core.remoting.impl.ssl;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;

public class CustomTrustManagerFactorySpi extends TrustManagerFactorySpi {

   private TrustManagerFactory trustManagerFactory;
   private TrustManager[] trustManagers;

   public CustomTrustManagerFactorySpi() throws NoSuchAlgorithmException, KeyStoreException, CertificateException, IOException {
      this.trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trustManagers = new TrustManager[1];
      trustManagers[0] = new CustomX509TrustManager(trustManagerFactory);
   }

   @Override
   protected void engineInit(KeyStore ks) throws KeyStoreException {
	   trustManagerFactory.init(ks);
   }

   @Override
   protected void engineInit(ManagerFactoryParameters spec) throws InvalidAlgorithmParameterException {
      trustManagerFactory.init(spec);
   }

   @Override
   protected TrustManager[] engineGetTrustManagers() {
      return trustManagers;
   }
}
