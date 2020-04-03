using System;
using System.Collections.Generic;
using System.IO;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace xades
{
    class WSSecurity
    {
        protected X509Certificate2 x509Certificate2;
        protected RSACryptoServiceProvider csp;

        public WSSecurity()
        {
        }

        public WSSecurity(X509Certificate2 x509Certificate2)
        {
            this.x509Certificate2 = x509Certificate2;
            this.csp = (RSACryptoServiceProvider)x509Certificate2.PrivateKey;
        }

        public WSSecurity(String sCertificate)
        {
            X509Store myCertsStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            myCertsStore.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert in myCertsStore.Certificates)
            {
                String sSubject = cert.Subject;
                if (sSubject.Contains(sCertificate))
                {
                    this.x509Certificate2 = cert;
                }
            }
            if (x509Certificate2 == null)
            {
                throw new Exception("Certificate " + sCertificate + " not found.");
            }
            this.csp = (RSACryptoServiceProvider)x509Certificate2.PrivateKey;
        }

        public String GetEnvelope(String action, String messageId, String body)
        {
            String sX509Cer_ID   = "X509-01";
            String sSignature_ID = "SIG-01";
            String sKeyInfo_ID   = "KI-01";
            String sTimestamp_ID = "TS-01";

            String created = GetTimestamp();
            String expires = GetTimestamp(5);

            SHA1Managed sha1 = new SHA1Managed();

            // Timestamp transformed c14n InclusiveNamespaces PrefixList=\"wsse wsa soapenv\"
            String ts = "<wsu:Timestamp";
            ts += " xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"";
            ts += " xmlns:wsa=\"http://www.w3.org/2005/08/addressing\"";
            ts += " xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"";
            ts += " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"";
            ts += " wsu:Id=\"" + sTimestamp_ID + "\">";
            ts += "<wsu:Created>" + created + "</wsu:Created>";
            ts += "<wsu:Expires>" + expires + "</wsu:Expires>";
            ts += "</wsu:Timestamp>";
            byte[] abTS = System.Text.Encoding.Default.GetBytes(ts);
            byte[] hsTS = sha1.ComputeHash(abTS);
            String sB64_DigestTS = System.Convert.ToBase64String(hsTS, Base64FormattingOptions.None);

            // SignedInfo transformed c14n InclusiveNamespaces PrefixList=\"wsa soapenv\"
            String si = "<ds:SignedInfo";
            si += " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"";
            si += " xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"";
            si += " xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">";
            si += "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">";
            si += "<ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"wsa soapenv\"></ec:InclusiveNamespaces>";
            si += "</ds:CanonicalizationMethod>";
            si += "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></ds:SignatureMethod>";
            si += "<ds:Reference URI=\"#" + sTimestamp_ID + "\">";
            si += "<ds:Transforms>";
            si += "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">";
            si += "<ec:InclusiveNamespaces xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\" PrefixList=\"wsse wsa s\"></ec:InclusiveNamespaces>";
            si += "</ds:Transform>";
            si += "</ds:Transforms>";
            si += "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></ds:DigestMethod>";
            si += "<ds:DigestValue>" + sB64_DigestTS + "</ds:DigestValue>";
            si += "</ds:Reference>";
            si += "</ds:SignedInfo>";
            byte[] abSI = System.Text.Encoding.Default.GetBytes(si);
            byte[] hsSI = sha1.ComputeHash(abSI);

            String sB64_Cert = "";
            if(x509Certificate2 != null)
            {
                sB64_Cert = System.Convert.ToBase64String(x509Certificate2.GetRawCertData(), Base64FormattingOptions.None);
            }

            // Sign the hash of SignedInfo
            String sSignatureValue = "";
            if (csp != null)
            {
                RSAPKCS1SignatureFormatter rsaPKCS1SignatureFormatter = new RSAPKCS1SignatureFormatter(csp);
                rsaPKCS1SignatureFormatter.SetHashAlgorithm("SHA1");
                byte[] signature = rsaPKCS1SignatureFormatter.CreateSignature(hsSI);

                sSignatureValue = System.Convert.ToBase64String(signature, Base64FormattingOptions.None);
            }

            // Envelope
            String r = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">";

            // Header
            r += "<soapenv:Header xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">";

            r += "<wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">";

            // BinarySecurityToken
            r += "<wsse:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\"";
            r += " ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"";
            r += " wsu:Id=\"" + sX509Cer_ID + "\">";
            r += sB64_Cert;
            r += "</wsse:BinarySecurityToken>";

            // Signature
            r += "<ds:Signature Id=\"" + sSignature_ID + "\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">";
            {
                // SignedInfo
                r += "<ds:SignedInfo>";
                r += "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">";
                r += "<ec:InclusiveNamespaces PrefixList=\"wsa soapenv\" xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>";
                r += "</ds:CanonicalizationMethod>";
                r += "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>";
                r += "<ds:Reference URI=\"#" + sTimestamp_ID + "\">";
                r += "<ds:Transforms>";
                r += "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">";
                r += "<ec:InclusiveNamespaces PrefixList=\"wsse wsa soapenv\" xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>";
                r += "</ds:Transform>";
                r += "</ds:Transforms>";
                r += "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>";
                r += "<ds:DigestValue>" + sB64_DigestTS + "</ds:DigestValue>";
                r += "</ds:Reference>";
                r += "</ds:SignedInfo>";
                // SignatureValue
                r += "<ds:SignatureValue>" + sSignatureValue + "</ds:SignatureValue>";
                // Key info
                r += "<ds:KeyInfo Id=\"" + sKeyInfo_ID + "\">";
                r += "<wsse:SecurityTokenReference wsu:Id=\"STR-01\">";
                r += "<wsse:Reference URI=\"#" + sX509Cer_ID + "\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/>";
                r += "</wsse:SecurityTokenReference>";
                r += "</ds:KeyInfo>";
            }
            r += "</ds:Signature>";
            
            // Timestamp
            r += "<wsu:Timestamp wsu:Id=\"" + sTimestamp_ID + "\">";
            r += "<wsu:Created>" + created + "</wsu:Created>";
            r += "<wsu:Expires>" + expires + "</wsu:Expires>";
            r += "</wsu:Timestamp>";
            r += "</wsse:Security>";
            
            // Addressing
            r += "<wsa:Action soapenv:mustUnderstand=\"1\">" + action  + "</wsa:Action>";
            r += "<wsa:MessageID soapenv:mustUnderstand=\"1\">" + messageId + "</wsa:MessageID>";
            r += "</soapenv:Header>";

            // Body
            r += "<soapenv:Body>";
            r += body;
            r += "</soapenv:Body>";

            r += "</soapenv:Envelope>";
            return r;
        }

        private String GetTimestamp()
        {
            DateTime dtCurrent = DateTime.Now.ToUniversalTime();
            String sYear = "" + dtCurrent.Year;
            String sMonth = dtCurrent.Month < 10 ? "0" + dtCurrent.Month : "" + dtCurrent.Month;
            String sDay = dtCurrent.Day < 10 ? "0" + dtCurrent.Day : "" + dtCurrent.Day;
            String sHour = dtCurrent.Hour < 10 ? "0" + dtCurrent.Hour : "" + dtCurrent.Hour;
            String sMinute = dtCurrent.Minute < 10 ? "0" + dtCurrent.Minute : "" + dtCurrent.Minute;
            String sSecond = dtCurrent.Second < 10 ? "0" + dtCurrent.Second : "" + dtCurrent.Second;
            return sYear + "-" + sMonth + "-" + sDay + "T" + sHour + ":" + sMinute + ":" + sSecond + "Z";
        }

        private String GetTimestamp(int minutes)
        {
            DateTime dtCurrent = DateTime.Now.ToUniversalTime().AddMinutes(minutes);
            String sYear = "" + dtCurrent.Year;
            String sMonth = dtCurrent.Month < 10 ? "0" + dtCurrent.Month : "" + dtCurrent.Month;
            String sDay = dtCurrent.Day < 10 ? "0" + dtCurrent.Day : "" + dtCurrent.Day;
            String sHour = dtCurrent.Hour < 10 ? "0" + dtCurrent.Hour : "" + dtCurrent.Hour;
            String sMinute = dtCurrent.Minute < 10 ? "0" + dtCurrent.Minute : "" + dtCurrent.Minute;
            String sSecond = dtCurrent.Second < 10 ? "0" + dtCurrent.Second : "" + dtCurrent.Second;
            return sYear + "-" + sMonth + "-" + sDay + "T" + sHour + ":" + sMinute + ":" + sSecond + "Z";
        }
    }
}
