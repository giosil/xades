using System;
using System.Collections.Generic;
using System.IO;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

namespace xades
{
    class XAdES
    {
        protected X509Certificate2 x509Certificate2;
        protected RSACryptoServiceProvider csp;

        public XAdES(X509Certificate2 x509Certificate2)
        {
            this.x509Certificate2 = x509Certificate2;
            this.csp = (RSACryptoServiceProvider)x509Certificate2.PrivateKey;
        }

        public XAdES(String sCertificate)
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
            this.csp = (RSACryptoServiceProvider) x509Certificate2.PrivateKey;
        }

        public String Sign(String sFolder, String sFileName, bool boEnveloped)
        {
            byte[] fileXML = File.ReadAllBytes(sFolder + "\\" + sFileName);

            return Sign(fileXML, boEnveloped);
        }

        public String Sign(String sXMLDocument, bool boEnveloped)
        {
            byte[] fileXML = System.Text.Encoding.Default.GetBytes(sXMLDocument);

            return Sign(fileXML, boEnveloped);
        }

        public byte[] C14NTransform(byte[] fileXML)
        {
            Stream stream = new MemoryStream(fileXML);

            XmlDsigC14NTransform xmlDsigC14NTransform = new XmlDsigC14NTransform(true);
            xmlDsigC14NTransform.LoadInput(stream);

            Type streamType = typeof(System.IO.Stream);
            MemoryStream outputStream = (MemoryStream)xmlDsigC14NTransform.GetOutput(streamType);

            return outputStream.ToArray();
        }

        public String Sign(byte[] fileXML, bool boEnveloped)
        {
            byte[] fileC14NXML = C14NTransform(fileXML);

            // Hash the data
            SHA256Managed sha256 = new SHA256Managed();
            byte[] hashFileXml = sha256.ComputeHash(fileC14NXML);

            String sB64_Hash = System.Convert.ToBase64String(hashFileXml, Base64FormattingOptions.None);
            String sB64_Cert = System.Convert.ToBase64String(x509Certificate2.GetRawCertData(), Base64FormattingOptions.None);

            String sKeyInfo = "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" Id=\"idKeyInfo\">";
            sKeyInfo += "<X509Data>";
            sKeyInfo += "<X509Certificate>" + sB64_Cert + "</X509Certificate>";
            sKeyInfo += "</X509Data>";
            sKeyInfo += "</KeyInfo>";
            byte[] abKeyInfo = System.Text.Encoding.Default.GetBytes(sKeyInfo);
            byte[] hashKeyInfo = sha256.ComputeHash(abKeyInfo);
            String sB64_HKey = System.Convert.ToBase64String(hashKeyInfo, Base64FormattingOptions.None);

            String sTimestamp = GetTimestamp();
            String sSignedProperties = "<SignedProperties xmlns=\"http://uri.etsi.org/01903/v1.3.2#\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" Id=\"idSignedProperties\">";
            sSignedProperties += "<SignedSignatureProperties>";
            sSignedProperties += "<SigningTime>" + sTimestamp + "</SigningTime>";
            sSignedProperties += "</SignedSignatureProperties>";
            sSignedProperties += "</SignedProperties>";
            byte[] abSignedProperties = System.Text.Encoding.Default.GetBytes(sSignedProperties);
            byte[] hashSignedProperties = sha256.ComputeHash(abSignedProperties);
            String sB64_HSPr = System.Convert.ToBase64String(hashSignedProperties, Base64FormattingOptions.None);

            String sIdRef_1 = "xmldsig-" + Guid.NewGuid().ToString("D");
            String sRef_1 = "<Reference Id=\"" + sIdRef_1 + "\" URI=\"\">";
            sRef_1 += "<Transforms>";
            sRef_1 += "<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform>";
            sRef_1 += "<Transform Algorithm=\"http://www.w3.org/2006/12/xml-c14n11#WithComments\"></Transform>";
            sRef_1 += "</Transforms>";
            sRef_1 += "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod>";
            sRef_1 += "<DigestValue>" + sB64_Hash + "</DigestValue>";
            sRef_1 += "</Reference>";

            String sIdRef_2 = "xmldsig-" + Guid.NewGuid().ToString("D");
            String sRef_2 = "<Reference Id=\"" + sIdRef_2 + "\" URI=\"#idKeyInfo\">";
            sRef_2 += "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod>";
            sRef_2 += "<DigestValue>" + sB64_HKey + "</DigestValue>";
            sRef_2 += "</Reference>";

            String sIdRef_3 = "xmldsig-" + Guid.NewGuid().ToString("D");
            String sRef_3 = "<Reference Id=\"" + sIdRef_3 + "\" Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#idSignedProperties\">";
            sRef_3 += "<DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></DigestMethod>";
            sRef_3 += "<DigestValue>" + sB64_HSPr + "</DigestValue>";
            sRef_3 += "</Reference>";

            String sSignedInfo = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">";
            sSignedInfo += "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2006/12/xml-c14n11#WithComments\"></CanonicalizationMethod>";
            sSignedInfo += "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></SignatureMethod>";
            sSignedInfo += sRef_1;
            sSignedInfo += sRef_2;
            sSignedInfo += sRef_3;
            sSignedInfo += "</SignedInfo>";
            byte[] abSignedInfo = System.Text.Encoding.Default.GetBytes(sSignedInfo);
            byte[] hashSignedInfo = sha256.ComputeHash(abSignedInfo);

            // Sign the hash of sSignedInfo
            RSAPKCS1SignatureFormatter rsaPKCS1SignatureFormatter = new RSAPKCS1SignatureFormatter(csp);
            rsaPKCS1SignatureFormatter.SetHashAlgorithm("SHA256");
            byte[] signature = rsaPKCS1SignatureFormatter.CreateSignature(hashSignedInfo);

            String sB64_Sign = System.Convert.ToBase64String(signature, Base64FormattingOptions.None);

            String sIdSignature = "xmldsig-" + Guid.NewGuid().ToString("D");
            String sXMLSignature = "<Signature Id=\"" + sIdSignature + "\" xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
            sXMLSignature += "<SignedInfo>";
            sXMLSignature += "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2006/12/xml-c14n11#WithComments\"></CanonicalizationMethod>";
            sXMLSignature += "<SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></SignatureMethod>";
            sXMLSignature += sRef_1;
            sXMLSignature += sRef_2;
            sXMLSignature += sRef_3;
            sXMLSignature += "</SignedInfo>";
            sXMLSignature += "<SignatureValue>" + sB64_Sign + "</SignatureValue>";
            sXMLSignature += "<KeyInfo Id=\"idKeyInfo\">";
            sXMLSignature += "<X509Data>";
            sXMLSignature += "<X509Certificate>" + sB64_Cert + "</X509Certificate>";
            sXMLSignature += "</X509Data>";
            sXMLSignature += "</KeyInfo>";
            sXMLSignature += "<Object Id=\"idObject\">";
            sXMLSignature += "<QualifyingProperties Target=\"#" + sIdSignature + "\" xmlns=\"http://uri.etsi.org/01903/v1.3.2#\">";
            sXMLSignature += "<SignedProperties Id=\"idSignedProperties\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">";
            sXMLSignature += "<SignedSignatureProperties>";
            sXMLSignature += "<SigningTime>" + sTimestamp + "</SigningTime>";
            sXMLSignature += "</SignedSignatureProperties>";
            sXMLSignature += "</SignedProperties>";
            sXMLSignature += "</QualifyingProperties>";
            sXMLSignature += "</Object>";
            sXMLSignature += "</Signature>";

            if (!boEnveloped)
            {
                return sXMLSignature;
            }

            String sOutput = System.Text.Encoding.Default.GetString(fileXML);
            String sSingatureCodeTag = "</signatureCode>";
            int iSignatureCode = sOutput.IndexOf(sSingatureCodeTag);
            if (iSignatureCode > 0)
            {
                int iStartSignature = iSignatureCode + sSingatureCodeTag.Length;
                return sOutput.Substring(0, iStartSignature) + sXMLSignature + sOutput.Substring(iStartSignature);
            }
            int iLastTag = sOutput.LastIndexOf("</");
            return sOutput.Substring(0, iLastTag) + sXMLSignature + sOutput.Substring(iLastTag);
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
    }

}
