import io.jsonwebtoken.Jwts;

import javax.net.ssl.*;
import java.io.*;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Main {

    static {
        disableSslVerification();
    }



    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, URISyntaxException {

        String xrfkey = "7rBHABt65vFflaZ7"; //Xrfkey to prevent cross-site issues
        String host = "localhost"; //Enter the Qlik Sense Server hostname here
        String vproxy = ""; //Enter the prefix for the virtual proxy configured in Qlik Sense Steps Step 1
        try
        {

            /************** BEGIN Certificate Acquisition **************/
            String certFolder = "C:\\ProgramData\\Qlik\\Sense\\Repository\\Exported Certificates\\.Local Certificates\\"; //This is a folder reference to the location of the jks files used for securing ReST communication
            String proxyCert = certFolder + "client.jks"; //Reference to the client jks file which includes the client certificate with private key
            String proxyCertPass="pppdddaaaeee"; //This is the password to access the Java Key Store information
            String rootCert = certFolder + "server.jks"; //Reference to the root certificate for the client cert. Required in this example because Qlik Sense certs are used.
            String rootCertPass = "pppdddaaaeee"; //This is the password to access the Java Key Store information
            /************** END Certificate Acquisition **************/

            /************** BEGIN Certificate configuration for use in connection **************/
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(new File(proxyCert)), proxyCertPass.toCharArray());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, proxyCertPass.toCharArray());
            SSLContext context = SSLContext.getInstance("SSL");
            KeyStore ksTrust = KeyStore.getInstance("JKS");
            ksTrust.load(new FileInputStream(rootCert), rootCertPass.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ksTrust);
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            SSLSocketFactory sslSocketFactory = context.getSocketFactory();
            /************** END Certificate configuration for use in connection **************/


            /************** BEGIN HTTPS Connection **************/
            System.out.println("Browsing to: " + "https://" + host + ":4243/qps/" + vproxy + "ticket?xrfkey=" + xrfkey);
            URL url = new URL("https://" + host + ":4243/qps" + vproxy + "/ticket?xrfkey=" + xrfkey);
            HttpsURLConnection connection = (HttpsURLConnection ) url.openConnection();
            connection.setSSLSocketFactory(sslSocketFactory);
            connection.setRequestProperty("x-qlik-xrfkey", xrfkey); connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestProperty("Content-Type","application/json");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestMethod("POST");
            /************** BEGIN JSON Message to Qlik Sense Proxy API **************/


            String body = "{ 'UserId':'Alex','UserDirectory':'.',";
            body+= "'Attributes': [],"; body+= "}"; System.out.println("Payload: " + body);
            /************** END JSON Message to Qlik Sense Proxy API **************/


            OutputStreamWriter wr= new OutputStreamWriter(connection.getOutputStream());
            wr.write(body);
            wr.flush(); //Get the response from the QPS BufferedReader
            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder builder = new StringBuilder();
            String inputLine;
            while ((inputLine = in.readLine()) != null)
            {
                builder.append(inputLine);
            }
            in.close();
            String data = builder.toString();
            System.out.println("The response from the server is: " + data);
            /************** END HTTPS Connection **************/
        }
        catch (KeyStoreException e) { e.printStackTrace(); }
        catch (IOException e) { e.printStackTrace(); }
        catch (CertificateException e) { e.printStackTrace(); }
        catch (NoSuchAlgorithmException e) { e.printStackTrace(); }
        catch (UnrecoverableKeyException e) { e.printStackTrace(); }
        catch (KeyManagementException e) { e.printStackTrace(); }
    }

    private static void disableSslVerification() {
        try
        {
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }
            };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
    }
}

//https://stackoverflow.com/questions/22296312/convert-certificate-from-pem-into-jks/22298627
