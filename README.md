# eSign India Integration Java  
eSign-India-Integration-Java is a ready java class that provides an easy way to interact with the eSign service provider, in order to perform eSign under Indian regulations.     

## Sample code 
### Initializing the ESign constructor
~~~Java
ESign esignobj = new ESign("ASPID", "Path\\DocSignerCertificate.pfx", "pfxpassword", "pfxalias", "SignDocURL");
~~~
### Sign Text
~~~Java
ESign.Response res = esignobj.signText("123456789012", "UniqueTransactionID ", "texttosign", AuthMode.FP, "eKYCRespXML", "documentInfo");
~~~
### Sign PDF
~~~Java
SignatureAppearance  appearance = new SignatureAppearance("To apply for loan","Bangalore",new Rectangle(25,25,250,250),1);
ESign.Response res = esignobj.signPDF("123456789012", "UniqueTransactionID ",  "PATH\\input.pdf",  "PATH \\output.pdf",  appearance ,  AuthMode.OTP, "eKYCRespXML", "documentInfo");
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
eSignURL|URL of ESP to post request to sign pdf/text.
