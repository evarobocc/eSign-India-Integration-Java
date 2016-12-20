/*
 * MIT License
 *
 * Copyright (c) 2016 eMudhra Limited
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 */
package esign;

import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * To generate OTP 
 * To eSign PDF or Text using OTP/FMR/IIR
 */
public class ESign {

    private static final XPath xPath = XPathFactory.newInstance().newXPath();
    private final String aspID;
    private final String pfxFilePath;
    private final String pfxPassword;
    private final String pfxAlias;
    private final String cerFilePath;
    private final String otpURL;
    private final String eSignURL;

    /**
     *
     * @param aspID
     * @param pfxFilePath
     * @param pfxPassword
     * @param pfxAlias
     * @param cerFilePath
     * @param otpURL
     * @param eSignURL
     * 
     */
    public ESign(String aspID, String pfxFilePath, String pfxPassword, String pfxAlias, String cerFilePath, String otpURL, String eSignURL) {
        this.aspID = aspID;
        this.pfxFilePath = pfxFilePath;
        this.pfxPassword = pfxPassword;
        this.pfxAlias = pfxAlias;
        this.cerFilePath = cerFilePath;
        this.otpURL = otpURL;
        this.eSignURL = eSignURL;
    }

    /**
     *
     * @param Aadhaarnumber
     * @param UniqueTransactionId
     * @return
     *
     */
    public Response getOTP(String Aadhaarnumber, String UniqueTransactionId) {
        int Aadhaarlength = 0;
        Response res = new Response();
        try {
            if (UniqueTransactionId == null || UniqueTransactionId.trim().equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Transaction id is not passed.");
                return res;
            }
            if (Aadhaarnumber == null || Aadhaarnumber.trim().equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Aadhaar number is not passed.");
                return res;
            }
            Aadhaarlength = (int) Math.log10(Long.parseLong(Aadhaarnumber)) + 1;
            if (Aadhaarlength < 12 || Aadhaarlength > 12) {
                res.setStatus(false);
                res.setErrorMessage("Length of aadhaar number is not valid.");
                return res;
            } else if (aspID == null || aspID.equals("")) {
                res.setStatus(false);
                res.setErrorMessage("ASP id is not passed.");
                return res;
            } else if (pfxFilePath == null || pfxFilePath.equals("")) {
                res.setStatus(false);
                res.setErrorMessage("PFX file path is not passed.");
                return res;
            } else if (pfxPassword == null || pfxPassword.equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Password of PFX file is not passed.");
                return res;
            } else if (pfxAlias == null || pfxAlias.equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Alias of PFX file is not passed.");
                return res;
            } else if (otpURL == null || otpURL.equals("")) {
                res.setStatus(false);
                res.setErrorMessage("OTP URL is not passed.");
                return res;
            } else {
                KeyStore.PrivateKeyEntry keyEntry = Utilities.getKeyFromKeyStore(pfxFilePath, pfxPassword.toCharArray(), pfxAlias);
                if (keyEntry == null) {
                    res.setStatus(false);
                    res.setErrorMessage("Utilities.getKeyFromKeyStore has returned null value.");
                    return res;
                }
                String RequestTs = Utilities.getCurrentDateTimeISOFormat();
                String rawXml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><OTP ver=\"1.0\" ts=\"" + RequestTs + "\" txn=\"" + UniqueTransactionId + "\" aspId=\"" + aspID + "\" uid=\"" + Aadhaarnumber + "\"></OTP>";
                Document XmlDoc = Utilities.convertStringToDocument(rawXml);
                String XmlSigned = Utilities.signXML(Utilities.convertDocumentToString(XmlDoc), true, keyEntry);
                String Xml = XmlSigned;
                String otpUrlParameters = URLEncoder.encode(Xml, "UTF-8");
                String otpResponseXml = Utilities.excutePostXml(otpURL, otpUrlParameters);
                Document doc = Utilities.convertStringToDocument(otpResponseXml);
                String errcode = Utilities.getXpathValue(xPath, "/OTPResp/@errCode", doc);
                String WsErrMsg = xPath.compile("/OTPResp/@errMsg").evaluate(doc);
                res.setErrorCode(errcode);
                res.setErrorMessage(WsErrMsg);                
                res.setResponseXML(otpResponseXml);
                res.setStatus(true);
                return res;
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            res.setStatus(false);
            res.setErrorMessage(e.getLocalizedMessage());
            return res;
        }
    }

    /**
     *
     * @param AadharNumber
     * @param AuthenticationValue
     * @param UniqueTransactionId
     * @param TextToBeSigned
     * @param details
     * @param authMode
     * @return
     * 
     */
    public Response signText(String AadharNumber, String AuthenticationValue, String UniqueTransactionId, String TextToBeSigned, AuthMetaDetails details, AuthMode authMode) {
        String eSignResponseXml = "";
        Response res = new Response();
        int Aadhaarlength = 0;
        String rawxml = "";
        try {
            if (AadharNumber == null || AadharNumber.trim().equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Aadhaar number is not passed.");
                return res;
            }
            if (AuthenticationValue == null || AuthenticationValue.trim().equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Authentication value is not passed.");
                return res;
            }
            if (UniqueTransactionId == null || UniqueTransactionId.trim().equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Transaction id is not passed.");
                return res;
            }
            if (TextToBeSigned == null || TextToBeSigned.trim().equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Text to sign is not passed.");
                return res;
            }
            Aadhaarlength = (int) Math.log10(Long.parseLong(AadharNumber)) + 1;
            if (Aadhaarlength < 12 || Aadhaarlength > 12) {
                res.setStatus(false);
                res.setErrorMessage("Length of aadhaar is not valid.");
                return res;
            }
            if (!(details.fdc.equals("NC") || details.fdc.equals("NA"))) {//
                res.setStatus(false);
                res.setErrorMessage("Invalid fdc value please set it as NC for Biometric or NA for non-Biometric");
                return res;
            }
            if (!(details.idc.equals("NC") || details.idc.equals("NA"))) {
                res.setStatus(false);
                res.setErrorMessage("Invalid idc value please set it as NC for Iris or NA for non-Iris");
                return res;
            }
            if (!(details.lot.equals("G") || details.lot.equals("P"))) {
                res.setStatus(false);
                res.setErrorMessage("Invalid lot value please set it as G for geo coding or P for postal pincode");
                return res;
            }
            if (authMode == null) {
                res.setStatus(false);
                res.setErrorMessage("Authmode type is empty");
                return res;
            }

            String lovpostal = "^[0-9]{1,6}$";
            String lovgeo = "^[0-9]{10}\\.{1}[0-9]{4}[,]{1}[0-9]{10}\\.{1}[0-9]{4}[,]{1}[0-9]{4}\\.{1}[0-9]{2}$";

            if (!((details.lov.matches(lovpostal) && details.lot.equals("P")) || (details.lot.equals("G") && details.lov.matches(lovgeo)))) {
                res.setStatus(false);
                res.setErrorMessage("Invalid lov value please set it to a 6 digit pincode number if lot value is P or to a geo-code value if lot value is G");
                return res;
            }
            if (!details.pip.equals("NA")) {
                res.setStatus(false);
                res.setErrorMessage("Invalid pip value please set it as NA");
                return res;
            }
            String pattern = "^[a-zA-Z0-9:]{1,20}$";
            if (!details.udc.matches(pattern)) {
                res.setStatus(false);
                res.setErrorMessage("Invalid udc value please set it as an alphanumeric value");
                return res;
            }

            MessageDigest mDigest = MessageDigest.getInstance("SHA-256");
            byte[] result;
            result = mDigest.digest(TextToBeSigned.getBytes("UTF8"));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < result.length; i++) {
                sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
            }
            String docHash = sb.toString();

            KeyStore.PrivateKeyEntry keyEntry = Utilities.getKeyFromKeyStore(pfxFilePath, pfxPassword.toCharArray(), pfxAlias);
            if (keyEntry == null) {
                res.setStatus(false);
                res.setErrorMessage("Utilities.getKeyFromKeyStore has returned null value.");
                return res;
            }
            String tid = "public";
            String ac = "";
            String lk = "";
            String sa = "";
            String timestamp = Utilities.getCurrentDateTimeISOFormat();

            String pvelement = "";
            int AuthMode = 0;
            switch (authMode) {
                case OTP:
                    pvelement = "<Pv otp=\"" + AuthenticationValue + "\"/>";
                    AuthMode = 1;
                    break;
                case FP:
                    pvelement = "<Bios><Bio type=\"FMR\" posh=\"UNKNOWN\">" + AuthenticationValue + "</Bio></Bios>";
                    AuthMode = 2;
                    break;
                case IRIS:
                    pvelement = "<Bios><Bio type=\"IIR\" posh=\"UNKNOWN\">" + AuthenticationValue + "</Bio></Bios>";
                    AuthMode = 3;
                    break;
            }
            String certificate_expiry = "";
            try {
                certificate_expiry = Utilities.getExpiryDate(cerFilePath);
            } catch (Exception e) {
                res.setStatus(false);
                res.setErrorMessage(e.getMessage());
                return res;
            }
            byte[] sessionKey = (null);
            byte[] encryptedSessionKey = (null);
            sessionKey = Utilities.generateSessionKey();
            try {
                encryptedSessionKey = Utilities.encryptUsingPublicKey(sessionKey, cerFilePath);
            } catch (Exception ex) {
                res.setStatus(false);
                res.setErrorMessage(ex.getMessage());
                return res;
            }
            String skey;
            skey = new String(Base64.encode(encryptedSessionKey), "UTF8");
            String pidxml = "<Pid xmlns=\"http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0\" ts=\"" + timestamp + "\" ver=\"1.0\">" + pvelement + "</Pid>";
            byte[] pidXmlBytes = pidxml.getBytes("UTF8");
            byte[] encXMLPIDData = (null);
            encXMLPIDData = Utilities.encryptUsingSessionKey(sessionKey, pidXmlBytes);

            String PidEncoded = new String(Base64.encode(encXMLPIDData), "UTF8");
            byte[] hmac = Utilities.generateSha256Hash(pidXmlBytes);
            byte[] encryptedHmacBytes = (null);
            encryptedHmacBytes = Utilities.encryptUsingSessionKey(sessionKey, hmac);
            String HashEncoded = new String(Base64.encode(encryptedHmacBytes), "UTF8");
            String AuthXml = "";
            String AuthHash = "";
            String esignxml = "";
            AuthXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Auth xmlns=\"http://www.uidai.gov.in/authentication/uid-auth-request/1.0\" uid=\"" + AadharNumber + "\" tid=\"" + tid + "\" ac=\"" + ac + "\" sa=\"" + sa + "\" ver=\"1.6\" txn=\"" + UniqueTransactionId + "\" lk=\"" + lk + "\"><Meta fdc=\"" + details.getFdc() + "\" idc=\"" + details.getIdc() + "\" lot=\"" + details.getLot() + "\" lov=\"" + details.getLov() + "\" pip=\"" + details.getPip() + "\" udc=\"" + details.getUdc() + "\"/><Skey ci=\"" + certificate_expiry + "\">" + skey + "</Skey><Data type=\"X\">" + PidEncoded + "</Data><Hmac>" + HashEncoded + "</Hmac></Auth>";
            AuthHash = Utilities.sha256(new String(Base64.encode(AuthXml.getBytes("UTF8")), "UTF8"));
            esignxml = "<Esign ver=\"1.6\" sc=\"Y\" ts=\"" + timestamp + "\" txn=\"" + UniqueTransactionId + "\" uid=\"" + AadharNumber + "\" aspId=\"" + aspID + "\" AuthMode=\"" + AuthMode + "\" responseSigType=\"" + "pkcs7" + "\" preVerified=\"" + "n" + "\">"
                    + "<Docs>\n"
                    + "<InputHash id=\"1\" hashAlgorithm=\"SHA256\">" + docHash + "</InputHash>\n"
                    + "</Docs>"
                    + "<AuthHash>" + AuthHash + "</AuthHash>"
                    + "</Esign>";

            Document XmlDoc = Utilities.convertStringToDocument(esignxml);
            String esignxmlSigned = Utilities.signXML(Utilities.convertDocumentToString(XmlDoc), true, keyEntry);
            String esignenocedxml = new String(Base64.encode(esignxmlSigned.getBytes("UTF8")), "UTF8");

            String AuthRequestXML = "";
            String authencodedxml = "";
            authencodedxml = new String(Base64.encode(AuthXml.getBytes("UTF8")), "UTF8");
            AuthRequestXML = "<Aadhaar>" + authencodedxml + "</Aadhaar>\n";
            rawxml = "<Request>\n"
                    + "<EsignXml>" + esignenocedxml + "</EsignXml>\n"
                    + AuthRequestXML + "</Request>";
            
            String eSignUrlParameters = URLEncoder.encode(rawxml, "UTF-8");
            eSignResponseXml = Utilities.excutePostXml(eSignURL, eSignUrlParameters);            
            res.setResponseXML(eSignResponseXml);
            String ResponseXml = eSignResponseXml;
            Document doc = Utilities.convertStringToDocument(ResponseXml);
            String pkcs7response = "false";
            String WsErrMsg = "";
            String RespStatus = Utilities.getXpathValue(xPath, "/EsignResp/@status", doc);
            if (RespStatus.equals("1")) {
                pkcs7response = "1-" + xPath.compile("/EsignResp/Signatures/DocSignature").evaluate(doc);
            } else {
                String errcode = Utilities.getXpathValue(xPath, "/EsignResp/@errCode", doc);
                res.setErrorCode(errcode);

                WsErrMsg = xPath.compile("/EsignResp/@errMsg").evaluate(doc);
                pkcs7response = "0-" + WsErrMsg;
            }

            String pkcsres = pkcs7response;
            String[] pkcsRespArr = pkcsres.split("-");
            String pkcsressuccessfailure = pkcsRespArr[0];
            String returnedstring = pkcsRespArr[1];
            if (!pkcsressuccessfailure.equals("0")) {
                res.setSignedText(returnedstring);
                res.setStatus(true);
                res.setErrorMessage("text signed successfully");
                return res;
            } else {
                res.setSignedText("");
                res.setStatus(false);
                res.setErrorMessage(WsErrMsg);
                return res;
            }
        } catch (RuntimeException ex) {
            throw ex;
        } catch (Exception ex) {
            res.setSignedText("");
            res.setStatus(false);
            res.setErrorMessage(ex.getLocalizedMessage());
            return res;
        }
    }

    /**
     *
     * @param AadharNumber
     * @param AuthenticationValue
     * @param UniqueTransactionId
     * @param Inputfilepath
     * @param Outputfilepath
     * @param details
     * @param userAppearance
     * @param authMode
     * @return
     * 
     */
    public Response signPDF(String AadharNumber, String AuthenticationValue, String UniqueTransactionId, String Inputfilepath, String Outputfilepath, AuthMetaDetails details, SignatureAppearance userAppearance, AuthMode authMode){
        String eSignResponseXml = "";
        Response res = new Response();
        int Aadhaarlength = 0;
        String rawxml = "";
        try {
            if (AadharNumber == null || AadharNumber.trim().equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Aadhaar number is not passed.");
                return res;
            }
            if (AuthenticationValue == null || AuthenticationValue.trim().equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Authentication value is not passed.");
                return res;
            }
            if (UniqueTransactionId == null || UniqueTransactionId.trim().equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Transaction id is not passed.");
                return res;
            }
            if (Inputfilepath == null || Inputfilepath.trim().equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Input file path is not passed.");
                return res;
            }
            if (Outputfilepath == null || Outputfilepath.trim().equals("")) {
                res.setStatus(false);
                res.setErrorMessage("Output file path is not passed.");
                return res;
            }
            Aadhaarlength = (int) Math.log10(Long.parseLong(AadharNumber)) + 1;
            if (Aadhaarlength < 12 || Aadhaarlength > 12) {
                res.setStatus(false);
                res.setErrorMessage("Length of aadhaar number is not valid.");
                return res;
            }
            if (!(details.fdc.equals("NC") || details.fdc.equals("NA"))) {//
                res.setStatus(false);
                res.setErrorMessage("Invalid fdc value please set it as NC for Biometric or NA for non-Biometric");
                return res;
            }
            if (!(details.idc.equals("NC") || details.idc.equals("NA"))) {
                res.setStatus(false);
                res.setErrorMessage("Invalid idc value please set it as NC for Iris or NA for non-Iris");
                return res;
            }
            if (!(details.lot.equals("G") || details.lot.equals("P"))) {
                res.setStatus(false);
                res.setErrorMessage("Invalid lot value please set it as G for geo coding or P for postal pincode");
                return res;
            }
            if (authMode == null) {
                res.setStatus(false);
                res.setErrorMessage("Authmode type is empty");
                return res;
            }

            String lovpostal = "^[0-9]{1,6}$";
            String lovgeo = "^[0-9]{10}\\.{1}[0-9]{4}[,]{1}[0-9]{10}\\.{1}[0-9]{4}[,]{1}[0-9]{4}\\.{1}[0-9]{2}$";

            if (!((details.lov.matches(lovpostal) && details.lot.equals("P")) || (details.lot.equals("G") && details.lov.matches(lovgeo)))) {
                res.setStatus(false);
                res.setErrorMessage("Invalid lov value please set it to a 6 digit pincode number if lot value is P or to a geo-code value if lot value is G");
                return res;
            }
            if (!details.pip.equals("NA")) {
                res.setStatus(false);
                res.setErrorMessage("Invalid pip value please set it as NA");
                return res;
            }
            String pattern = "^[a-zA-Z0-9:]{1,20}$";
            if (!details.udc.matches(pattern)) {
                res.setStatus(false);
                res.setErrorMessage("Invalid udc value please set it as an alphanumeric value");
                return res;
            }
            PdfReader readerpdf = new PdfReader(Inputfilepath);
            OutputStream fout = new FileOutputStream(Outputfilepath);

            PdfStamper stamperpdf = PdfStamper.createSignature(readerpdf, fout, '\0',null,true);
            PdfSignatureAppearance appearance = stamperpdf.getSignatureAppearance();
            appearance.setReason(userAppearance.getReason());
            appearance.setLocation(userAppearance.getLocation());
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.MINUTE, 5);
            appearance.setSignDate(cal);

            appearance.setAcro6Layers(true);
            appearance.setCertificationLevel(PdfSignatureAppearance.NOT_CERTIFIED);
            appearance.setImage(null);

            appearance.setVisibleSignature(userAppearance.getCoordinates(), userAppearance.getPageNumber(), null);
            int contentEstimated = 8192;
            HashMap<PdfName, Integer> exc = new HashMap<>();
            exc.put(PdfName.CONTENTS, contentEstimated * 2 + 2);
            PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
            dic.setReason(appearance.getReason());
            dic.setLocation(appearance.getLocation());
            dic.setContact(appearance.getContact());
            dic.setDate(new PdfDate(appearance.getSignDate()));
            appearance.setCryptoDictionary(dic);
            appearance.preClose(exc);
            InputStream data = appearance.getRangeStream();
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte buf[] = new byte[contentEstimated];
            int n = 0;
            while ((n = data.read(buf, 0, contentEstimated)) > 0) {
                messageDigest.update(buf, 0, n);
            }
            byte hash[] = messageDigest.digest();
            byte[] reqBytesdata = Hex.encode(hash);
            String docHash = new String(reqBytesdata, "UTF8");

            KeyStore.PrivateKeyEntry keyEntry = Utilities.getKeyFromKeyStore(pfxFilePath, pfxPassword.toCharArray(), pfxAlias);
            if (keyEntry == null) {
                res.setStatus(false);
                res.setErrorMessage("Utilities.getKeyFromKeyStore has returned null value.");
                return res;
            }
            String tid = "public";
            String ac = "";
            String lk = "";
            String sa = "";
            String timestamp = Utilities.getCurrentDateTimeISOFormat();

            String pvelement = "";
            int AuthMode = 0;
            switch (authMode) {
                case OTP:
                    pvelement = "<Pv otp=\"" + AuthenticationValue + "\"/>";
                    AuthMode = 1;
                    break;
                case FP:
                    pvelement = "<Bios><Bio type=\"FMR\" posh=\"UNKNOWN\">" + AuthenticationValue + "</Bio></Bios>";
                    AuthMode = 2;
                    break;
                case IRIS:
                    pvelement = "<Bios><Bio type=\"IIR\" posh=\"UNKNOWN\">" + AuthenticationValue + "</Bio></Bios>";
                    AuthMode = 3;
                    break;
            }
            String certificate_expiry = "";
            try {
                certificate_expiry = Utilities.getExpiryDate(cerFilePath);
            } catch (Exception e) {
                res.setStatus(false);
                res.setErrorMessage(e.getMessage());
                return res;
            }
            byte[] sessionKey = null;
            byte[] encryptedSessionKey = null;
            sessionKey = Utilities.generateSessionKey();
            try {
                encryptedSessionKey = Utilities.encryptUsingPublicKey(sessionKey, cerFilePath);
            } catch (Exception ex) {
                res.setStatus(false);
                res.setErrorMessage(ex.getMessage());
                return res;
            }
            String skey = new String(Base64.encode(encryptedSessionKey), "UTF8");
            String pidxml = "<Pid xmlns=\"http://www.uidai.gov.in/authentication/uid-auth-request-data/1.0\" ts=\"" + timestamp + "\" ver=\"1.0\">" + pvelement + "</Pid>";
            byte[] pidXmlBytes = pidxml.getBytes("UTF8");
            byte[] encXMLPIDData = null;
            encXMLPIDData = Utilities.encryptUsingSessionKey(sessionKey, pidXmlBytes);

            String PidEncoded = new String(Base64.encode(encXMLPIDData), "UTF8");
            byte[] hmac = Utilities.generateSha256Hash(pidXmlBytes);
            byte[] encryptedHmacBytes = null;
            encryptedHmacBytes = Utilities.encryptUsingSessionKey(sessionKey, hmac);
            String HashEncoded = new String(Base64.encode(encryptedHmacBytes), "UTF8");
            String AuthXml = "";
            String AuthHash = "";
            String esignxml = "";
            AuthXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Auth xmlns=\"http://www.uidai.gov.in/authentication/uid-auth-request/1.0\" uid=\"" + AadharNumber + "\" tid=\"" + tid + "\" ac=\"" + ac + "\" sa=\"" + sa + "\" ver=\"1.6\" txn=\"" + UniqueTransactionId + "\" lk=\"" + lk + "\"><Meta fdc=\"" + details.getFdc() + "\" idc=\"" + details.getIdc() + "\" lot=\"" + details.getLot() + "\" lov=\"" + details.getLov() + "\" pip=\"" + details.getPip() + "\" udc=\"" + details.getUdc() + "\"/><Skey ci=\"" + certificate_expiry + "\">" + skey + "</Skey><Data type=\"X\">" + PidEncoded + "</Data><Hmac>" + HashEncoded + "</Hmac></Auth>";
            AuthHash = Utilities.sha256(new String(Base64.encode(AuthXml.getBytes("UTF8")), "UTF8"));
            esignxml = "<Esign ver=\"1.6\" sc=\"Y\" ts=\"" + timestamp + "\" txn=\"" + UniqueTransactionId + "\" uid=\"" + AadharNumber + "\" aspId=\"" + aspID + "\" AuthMode=\"" + AuthMode + "\" responseSigType=\"" + "pkcs7" + "\" preVerified=\"" + "n" + "\">"
                    + "<Docs>\n"
                    + "<InputHash id=\"1\" hashAlgorithm=\"SHA256\">" + docHash + "</InputHash>\n"
                    + "</Docs>"
                    + "<AuthHash>" + AuthHash + "</AuthHash>"
                    + "</Esign>";

            Document XmlDoc = Utilities.convertStringToDocument(esignxml);
            String esignxmlSigned = Utilities.signXML(Utilities.convertDocumentToString(XmlDoc), true, keyEntry);
            String esignenocedxml = new String(Base64.encode(esignxmlSigned.getBytes("UTF8")), "UTF8");

            String AuthRequestXML = "";
            String authencodedxml = "";
            authencodedxml = new String(Base64.encode(AuthXml.getBytes("UTF8")),"UTF8");
            AuthRequestXML = "<Aadhaar>" + authencodedxml + "</Aadhaar>\n";
            rawxml = "<Request>\n"
                    + "<EsignXml>" + esignenocedxml + "</EsignXml>\n"
                    + AuthRequestXML + "</Request>";
            
            String eSignurl = eSignURL;
            String eSignUrlParameters = URLEncoder.encode(rawxml, "UTF-8");
            eSignResponseXml = Utilities.excutePostXml(eSignurl, eSignUrlParameters);
            res.setResponseXML(eSignResponseXml);
            String ResponseXml = eSignResponseXml;
            Document doc = Utilities.convertStringToDocument(ResponseXml);
            //Read the Public Key
            String pkcs7response;
            String WsErrMsg = "";
            String RespStatus = Utilities.getXpathValue(xPath, "/EsignResp/@status", doc);
            if (RespStatus.equals("1")) {
                pkcs7response = "1-" + xPath.compile("/EsignResp/Signatures/DocSignature").evaluate(doc);
            } else {
                String errcode = Utilities.getXpathValue(xPath, "/EsignResp/@errCode", doc);
                res.setErrorCode(errcode);
                WsErrMsg = xPath.compile("/EsignResp/@errMsg").evaluate(doc);
                pkcs7response = "0-" + WsErrMsg;
            }

            String pkcsres = pkcs7response;
            String[] result = pkcsres.split("-");
            String pkcsressuccessfailure = result[0];
            String returnedstring = result[1];
            if (!pkcsressuccessfailure.equals("0")) {
                byte[] PKCS7Response = Base64.decode(returnedstring.getBytes("UTF8"));
                byte[] paddedSig = new byte[contentEstimated];
                System.arraycopy(PKCS7Response, 0, paddedSig, 0, PKCS7Response.length);
                PdfDictionary dic2 = new PdfDictionary();
                dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
                appearance.close(dic2);
                res.setStatus(true);
                res.setErrorMessage("Pdf is signed successfully");
                return res;
            } else {
                res.setStatus(false);
                res.setErrorMessage(WsErrMsg);
                return res;
            }
        } catch (RuntimeException ex) {
            throw ex;
        } catch (Exception ex) {
            res.setStatus(false);
            res.setErrorMessage(ex.toString());
            return res;
        }
    }

    /**
     * Response of getOTP, signText and signPDF methods of ESign Class
     */
    public static class Response {

        private String ErrorCode;              
        private String ErrorMessage;
        private Boolean Status;       
        private String ResponseXML;
        private String SignedText;

        /**
         * @return the ErrorMessage
         */
        public String getErrorMessage() {
            return ErrorMessage;
        }

        /**
         * @param ErrorMessage the ErrorMessage to set
         */
        protected void setErrorMessage(String ErrorMessage) {
            this.ErrorMessage = ErrorMessage;
        }

        /**
         * @return the Status
         */
        public Boolean getStatus() {
            return Status;
        }

        /**
         * @param Status the Status to set
         */
        protected void setStatus(Boolean Status) {
            this.Status = Status;
        }

        /**
         * @return the ResponseXML
         */
        public String getResponseXML() {
            return ResponseXML;
        }

        /**
         * @param ResponseXML the ResponseXML to set
         */
        protected void setResponseXML(String ResponseXML) {
            this.ResponseXML = ResponseXML;
        }
        
        /**
         * @return the SignedText
         */
        public String getSignedText() {
            return SignedText;
        }

        /**
         * @param SignedText the SignedText to set
         */
        public void setSignedText(String SignedText) {
            this.SignedText = SignedText;
        }

        /**
         * @return the ErrorCode
         */
        public String getErrorCode() {
            return ErrorCode;
        }

        /**
         * @param ErrorCode the ErrorCode to set
         */
        public void setErrorCode(String ErrorCode) {
            this.ErrorCode = ErrorCode;
        }
    }

    /**
     * Auth Meta Details used to construct AuthXML
     */
    public static class AuthMetaDetails {
        private final String fdc;
        private final String idc;
        private final String lot;
        private final String lov;
        private final String pip;
        private final String udc;

        /**
         *
         * @param fdc
            (mandatory) Fingerprint device code. This is a unique code provided for
            the fingerprint sensor-extractor combination. AUAs will have access to this code
            through UIDAI portal. This is an alpha-numeric string of maximum length 10.
            o While using fingerprint authentication, this code is mandatory and should
            be provided. If the code is unknown or device is not certified yet, use “NC”.
            o For non fingerprint authentication (when not using “bio” type “FMR” or
            “FIR”), use the value “NA”
         * @param idc
            (mandatory) Iris device code. This is a unique code provided for the iris
            sensor-extractor combination. AUAs will have access to this code through UIDAI
            portal. This is an alpha-numeric string of maximum length 10.
            o While using iris authentication, this code is mandatory and should be
            provided. If the code is unknown or device is not certified yet, use “NC”.
            o For non iris authentication, use the value “NA”
         * @param lot
            (mandatory) Location type. Valid values are “G” and “P”.
            o G – stands for geo coding in lat, long format
            o P – stands for postal pin code
         * @param lov
            (mandatory) Location Value.
            o If “lot” value is “G” then, this “lov” attribute must carry actual “lat,long,alt”
            of the location. Can be derived using GPS or using alternate method.
            Lat/Long should be in positive or negative decimal format (ISO 6709).
            Altitude is optional and may be populated if available.
            o If “lot” value is “P” then, this “lov” attribute must have a valid 6-digit
            postal pin code.
         * @param pip
            (mandatory) Public IP address of the device. If the device is connected to
            Internet and has a public IP, then this must be populated with that IP address. If
            the device has a private IP and is behind a router/proxy/etc, then public IP
            address of the router/proxy/etc should be set. If no public IP is available, leave it
            as “NA”.
         * @param udc
            (mandatory) Unique Device Code. This is a unique code for the
            authentication device assigned within the AUA domain. This is an alpha-numeric
            string of maximum length 20.
            o This allows better reporting and tracking of devices as well as help
            resolve issues at the device level.
            o It is highly recommended that AUAs define a unique codification scheme
            for all their devices.
            o Suggested format is “[vendorcode][date of deployment][serial number]”
         */
        public AuthMetaDetails(String fdc,String idc,String lot,String lov,String pip,String udc)
        {
            this.fdc = fdc;
            this.idc= idc;
            this.lot = lot;
            this.lov = lov;
            this.pip = pip;
            this.udc = udc;            
        }

        /**
         * @return the fdc
         */
        protected String getFdc() {
            return fdc;
        }

        /**
         * @return the idc
         */
        protected String getIdc() {
            return idc;
        }

        /**
         * @return the lot
         */
        protected String getLot() {
            return lot;
        }

        /**
         * @return the lov
         */
        protected String getLov() {
            return lov;
        }

        /**
         * @return the pip
         */
        protected String getPip() {
            return pip;
        }

        /**
         * @return the udc
         */
        protected String getUdc() {
            return udc;
        }        
    }

    /**
     * Detail of signature appearance
     */
    public static class SignatureAppearance {
        private final String reason;
        private final String location;
        private final Rectangle coordinates;
        private final int pageNumber;

        /**
         *
         * @param reason
         * Reason of signing. Ex. To apply for loan
         * @param location
         * Location of signing. Ex. Bangalore North
         * @param coordinates
         * Object of com.itextpdf.text.Rectangle
         * @param pageNumber
         * Page number on which signature is to display
         * 
         */
        public SignatureAppearance(String reason,String location,Rectangle coordinates,int pageNumber)
        {
            this.reason = reason;
            this.location = location;
            this.coordinates = coordinates;
            this.pageNumber = pageNumber;
        }

        /**
         * @return the reason
         */
        public String getReason() {
            return reason;
        }

        /**
         * @return the location
         */
        public String getLocation() {
            return location;
        }

        /**
         * @return the coordinates
         */
        public Rectangle getCoordinates() {
            return coordinates;
        }

        /**
         * @return the pageNumber
         */
        public int getPageNumber() {
            return pageNumber;
        }
    }

    /**
     * Mode of authentication
     */
    public enum AuthMode {

        /**
         * If authentication mode is OTP.
         */
        OTP,
        /**
         * If authentication mode is Fingerprint The biometric data should be of
         * type “Fingerprint Minutiae Record (FMR)”. This data should be in ISO
         * minutiae format with no proprietary extensions allowed.
         */
        FP,
        /**
         * If authentication mode is IRIS The biometric data should be of type
         * “Iris Image Record (IIR)”. The data should be an iris image packaged
         * in ISO 19794-6 format, which could contain a compressed (or
         * uncompressed) image having type PNG or Jpeg2000.
         */
        IRIS;
    }

    private static class Utilities {

        private static final Provider providerBC = new BouncyCastleProvider();
        private static final String prov = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");

        public static KeyStore.PrivateKeyEntry getKeyFromKeyStore(String keyStoreFile, char[] keyStorePassword, String alias) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, CertificateException {
            FileInputStream keyFileStream = null;
            try {
                KeyStore ks = KeyStore.getInstance("PKCS12");
                keyFileStream = new FileInputStream(keyStoreFile);
                ks.load(keyFileStream, keyStorePassword);
                KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(keyStorePassword));
                keyFileStream.close();
                return entry;
            } catch (RuntimeException ex) {
                if (keyFileStream != null) {
                    keyFileStream.close();
                }
                throw ex;
            } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException ex) {
                if (keyFileStream != null) {
                    keyFileStream.close();
                }
                throw ex;
            }
        }

        public static String signXML(String xmlDocument, boolean includeKeyInfo, KeyStore.PrivateKeyEntry keyEntry) throws TransformerException, ParserConfigurationException, Exception {
            // Parse the input XML
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            Document inputDocument = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(xmlDocument)));
            // Sign the input XML's DOM document
            Document signedDocument = sign(inputDocument, includeKeyInfo, keyEntry);
            // Convert the signedDocument to XML String
            StringWriter stringWriter = new StringWriter();
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            trans.transform(new DOMSource(signedDocument), new StreamResult(stringWriter));
            return stringWriter.getBuffer().toString();
        }

        public static String excutePostXml(String targetURL, String urlParameters) throws IOException, SQLException, NoSuchAlgorithmException, KeyManagementException {
            String ResponseXml = null;
            if (targetURL.matches("^(https)://.*$")) {
                ResponseXml = excutePostHttpsXml(targetURL, urlParameters);
            } else {
                ResponseXml = excutePostHttpXml(targetURL, urlParameters);
            }
            return ResponseXml;
        }

        public static String getExpiryDate(String certFile) throws Exception {
            X509Certificate cert = getX509Certificate(certFile);
            Date getExpiryDate = cert.getNotAfter();
            String stringDate = convertDateToString(getExpiryDate);
            return stringDate;
        }

        public static byte[] generateSessionKey() throws NoSuchAlgorithmException, NoSuchProviderException {
            int SYMMETRIC_KEY_SIZE = 256;
            KeyGenerator kgen = KeyGenerator.getInstance("AES", providerBC);
            kgen.init(SYMMETRIC_KEY_SIZE);
            SecretKey key = kgen.generateKey();
            byte[] symmKey = key.getEncoded();
            return symmKey;
        }

        public static byte[] encryptUsingPublicKey(byte[] data, String UidaiEncryptionCerFilePath) throws IOException, GeneralSecurityException, Exception {
            String ASYMMETRIC_ALGO = "RSA/ECB/PKCS1Padding";
            PublicKey PublicKeystring = getCertificateFromFile(UidaiEncryptionCerFilePath).getPublicKey();
            Cipher pkCipher = Cipher.getInstance(ASYMMETRIC_ALGO, providerBC);
            pkCipher.init(Cipher.ENCRYPT_MODE, PublicKeystring);
            byte[] encSessionKey = pkCipher.doFinal(data);
            return encSessionKey;
        }

        public static byte[] encryptUsingSessionKey(byte[] skey, byte[] data) throws InvalidCipherTextException {
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new AESEngine(), new PKCS7Padding());
            cipher.init(true, new KeyParameter(skey));
            int outputSize = cipher.getOutputSize(data.length);
            byte[] tempOP = new byte[outputSize];
            int processLen = cipher.processBytes(data, 0, data.length, tempOP, 0);
            int outputLen = cipher.doFinal(tempOP, processLen);
            byte[] result = new byte[processLen + outputLen];
            System.arraycopy(tempOP, 0, result, 0, result.length);
            return result;
        }

        public static byte[] generateSha256Hash(byte[] message) throws NoSuchAlgorithmException {
            String algorithm = "SHA-256";
            byte[] hash = null;
            MessageDigest digest;
            digest = MessageDigest.getInstance(algorithm, providerBC);
            digest.reset();
            hash = digest.digest(message);
            return hash;
        }

        public static String sha256(String base) throws UnsupportedEncodingException, NoSuchAlgorithmException {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(base.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < hash.length; i++) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        }

        public static String getCurrentDateTimeISOFormat() {
            java.util.Date dt = new java.util.Date();
            java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
            String currentTime = sdf.format(dt);
            return currentTime;
        }

        public static Document convertStringToDocument(String xmlStr) throws SAXException, ParserConfigurationException, IOException {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder;
            builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlStr)));
            return doc;
        }

        public static String convertDocumentToString(Document doc) throws TransformerException {
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer;

            transformer = tf.newTransformer();
            // below code to remove XML declaration
            // transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(writer));
            String output = writer.getBuffer().toString();
            return output;

        }

        public static Document sign(Document xmlDoc, boolean includeKeyInfo, KeyStore.PrivateKeyEntry keyEntry)
                throws Exception {
            if (System.getenv("SKIP_DIGITAL_SIGNATURE") != null) {
                return xmlDoc;
            }
            // Creating the XMLSignature factory.
            XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(prov).newInstance());
            DigestMethod digestMethod = factory.newDigestMethod(DigestMethod.SHA1, null);
            Transform transform = factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
            Reference reference = factory.newReference("", digestMethod, Collections.singletonList(transform), null, null);
            CanonicalizationMethod canonicalizationMethod = factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null);
            SignatureMethod signatureMethod = factory.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
            SignedInfo sInfo = factory.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(reference));
            //keyEntry = getKeyFromKeyStore(AspSigngingPfxFilePath, AspSigngingPfxPassword.toCharArray(), AspSigngingPfxAlias);
            if (keyEntry == null) {
                throw new RuntimeException("Key could not be read for digital signature. Please check value of signature alias and signature password, and restart the Auth Client");
            }
            X509Certificate x509Cert = (X509Certificate) keyEntry.getCertificate();
            KeyInfo kInfo = getKeyInfo(x509Cert, factory);
            DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), xmlDoc.getDocumentElement());
            XMLSignature signature = factory.newXMLSignature(sInfo, includeKeyInfo ? kInfo : null);
            signature.sign(dsc);
            Node node = dsc.getParent();
            return node.getOwnerDocument();
        }

        public static String excutePostHttpsXml(String targetURL, String urlParameters) throws IOException, SQLException, NoSuchAlgorithmException, KeyManagementException {

            URL url;
            HttpsURLConnection connection = null;
            SSLContext sslcontext = null;

            sslcontext = SSLContext.getInstance("SSL");

            sslcontext.init(new KeyManager[0],
                    new TrustManager[]{new DummyTrustManager()},
                    new SecureRandom());

            try {
                //Create connection
                SSLSocketFactory factory = sslcontext.getSocketFactory();
                url = new URL(targetURL);
                connection = (HttpsURLConnection) url.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Content-Type", "application/xml");
                connection.setRequestProperty("Content-Length", "" + Integer.toString(urlParameters.getBytes("UTF8").length));
                connection.setRequestProperty("Content-Language", "en-US");
                connection.setUseCaches(false);
                connection.setDoInput(true);
                connection.setDoOutput(true);
                connection.setSSLSocketFactory(factory);
                connection.setHostnameVerifier(new DummyHostnameVerifier());

                //Send request
                try (
                        DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
                    wr.writeBytes(urlParameters);
                    wr.flush();
                }
                InputStream is;
                is = connection.getInputStream();
                StringBuffer response;
                try (BufferedReader rd = new BufferedReader(new InputStreamReader(is, "UTF8"))) {
                    String line;
                    response = new StringBuffer();
                    while ((line = rd.readLine()) != null) {
                        response.append(line);
                        response.append('\r');
                    }
                }
                return response.toString();
            } catch (RuntimeException ex) {
                throw ex;
            } catch (Exception e) {
                return e.toString();
            } finally {

                if (connection != null) {
                    connection.disconnect();
                }
            }
        }

        public static String excutePostHttpXml(String targetURL, String urlParameters) throws IOException, SQLException {
            URL url;
            HttpURLConnection connection = null;

            //Create connection
            url = new URL(targetURL);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/xml");
            connection.setRequestProperty("Content-Length", "" + Integer.toString(urlParameters.getBytes("UTF8").length));
            connection.setRequestProperty("Content-Language", "en-US");
            connection.setUseCaches(false);
            connection.setDoInput(true);
            connection.setDoOutput(true);
            try ( //Send request
                    DataOutputStream wr = new DataOutputStream(
                            connection.getOutputStream())) {
                        wr.writeBytes(urlParameters);
                        wr.flush();
                    }
                    StringBuffer response;
                    try ( //Get Response
                            BufferedReader in = new BufferedReader(
                                    new InputStreamReader(connection.getInputStream(), "UTF8"))) {
                                String inputLine;
                                response = new StringBuffer();
                                //System.out.println("response" + response);
                                while ((inputLine = in.readLine()) != null) {
                                    response.append(inputLine);
                                }
                            }
                            //System.out.println("POST Response Code :: " + responseCode);
                            //System.out.println(response.toString());
                            return response.toString();

        }

        public static String getXpathValue(XPath xPath, String RequestPath, Document doc) throws XPathExpressionException {
            String XpathValue = xPath.compile(RequestPath).evaluate(doc);
            xPath.reset();
            return XpathValue;
        }

        public static X509Certificate getX509Certificate(String certFile) throws Exception {
            FileInputStream fis = null;
            try {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                fis = new FileInputStream(certFile);
                X509Certificate cert = (X509Certificate) factory.generateCertificate(fis);
                fis.close();
                return cert;
            } catch (RuntimeException ex) {
                if (fis != null) {
                    fis.close();
                }
                throw ex;
            } catch (CertificateException | IOException ex) {
                if (fis != null) {
                    fis.close();
                }
                throw ex;
            }
        }

        public static String convertDateToString(Date date) {
            String DATE_FORMAT_NOW = "yyyyMMdd";
            //Date date = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT_NOW);
            String stringDate = null;
            stringDate = sdf.format(date);

            return stringDate;
        }

        public static X509Certificate getCertificateFromFile(String certificateFile) throws IOException, CertificateException {
            FileInputStream fis = null;
            try {
                ByteArrayInputStream bais = null;
                // use FileInputStream to read the file
                fis = new FileInputStream(certificateFile);
                // read the bytes
                byte value[] = new byte[fis.available()];
                int read = fis.read(value);
                bais = new ByteArrayInputStream(value);
                // get X509 certificate factory
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                fis.close();
                // certificate factory can now create the certificate
                return (X509Certificate) certFactory.generateCertificate(bais);
            } catch (RuntimeException ex) {
                if (fis != null) {
                    fis.close();
                }
                throw ex;
            } catch (IOException | CertificateException ex) {
                if (fis != null) {
                    fis.close();
                }
                throw ex;
            }
        }

        @SuppressWarnings("unchecked")
        public static KeyInfo getKeyInfo(X509Certificate cert, XMLSignatureFactory fac) {
            // Create the KeyInfo containing the X509Data.
            KeyInfoFactory kif = fac.getKeyInfoFactory();
            List x509Content = new ArrayList();
            x509Content.add(cert.getSubjectX500Principal().getName());
            x509Content.add(cert);
            X509Data xd = kif.newX509Data(x509Content);
            return kif.newKeyInfo(Collections.singletonList(xd));
        }
    }

    private static class DummyHostnameVerifier implements HostnameVerifier {

        public boolean verify(String urlHostname, String certHostname) {
            return true;
        }

        @Override
        public boolean verify(String arg0, SSLSession arg1) {
            return true;
        }
    }

    private static class DummyTrustManager implements X509TrustManager {

        public DummyTrustManager() {
        }

        public boolean isClientTrusted(X509Certificate cert[]) {
            return true;
        }

        public boolean isServerTrusted(X509Certificate cert[]) {
            return true;
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {

        }
    }
}
