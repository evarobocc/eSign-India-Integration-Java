# eSign India Integration Java  
eSign-India-Integration-Java is a ready java class that provides an easy way to interact with the eSign service provider, in order to perform eSign under Indian regulations. 

### Features available:
1.	Generate OTP
2.	eSign Text data (For plain text, JSON, etc)   
   a.	Using Raw OTP / FP / IRIS    
  `b.	Using Constructed Auth XML (To do)`     
  `c.	Using Constructed Pre - KYC XML (To do)`     
3.	eSign PDF file    
   a.	Using Raw OTP / FP / IRIS   
  `b.	Using Constructed Auth XML (To do)`   
  `c.	Using Constructed Pre - KYC XML (To do)`    

## Sample code 
### Initializing the ESign constructor
~~~Java
ESign esignobj = new ESign("ASPID", "Path\\DocSignerCertificate.pfx", "pfxpassword", "pfxalias", "Path\\uidai_auth_prod.cer", "GetOTPURL", "SignDocURL");
~~~
### Generate OTP
~~~Java
ESign.Response res = esignobj.getOTP("123456789012","UniqueTransactionID");
~~~
### Sign Text
~~~Java
ESign.AuthMetaDetails details = new ESign.AuthMetaDetails("NC","NA","P","560103","NA","EMSANDBOX");
ESign.Response res = esignobj.signText("123456789012", "OTP/FMR/IIR", " UniqueTransactionID ", "texttosign", details, AuthMode.FP);
~~~
### Sign PDF
~~~Java
ESign.AuthMetaDetails details = new ESign.AuthMetaDetails("NC","NA","P","560103","NA","EMSANDBOX");
SignatureAppearance  appearance = new SignatureAppearance("To apply for loan","Bangalore",new Rectangle(25,25,250,250),1);
ESign.Response res = esignobj.signPDF("123456789012",  "OTP/FMR/IIR", " UniqueTransactionID ",  "PATH\\input.pdf",  "PATH \\output.pdf",  details, appearance ,  AuthMode.OTP);
~~~

## Dependency
1. itextpdf-5.5.5.jar
2. bcprov-jdk15on-1.54.jar

## Reference
Parameter|Description
----------------- | -------------
aspID       |ASP ID provided by ESP
pfxFilePath|Path of the document signer certificate file (.pfx/.p12) required for signing eSign/OTP xml requests. Can be in any physical location with read permission. 
pfxPassword	|Password of .pfx/.p12 file. 
pfxAlias|Alias of pfx file. 
cerFilePath|Public encryption certificate from [UIDAI (Production)](http://uidai.gov.in/images/authentication/uidai_auth_prod.zip). 
otpURL|URL of ESP to post request to generate OTP. 
eSignURL|URL of ESP to post request to sign pdf/text.
