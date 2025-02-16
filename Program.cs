using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Pkcs;

class Program
{
    static void Main(string[] args)
    {
        string sourcePdf = "../../../test.pdf";
        string signedPdf = "../../../signed.pdf";
        string signedLtvPdf = "../../../signed-ltv.pdf";
        string certPath = "../../../keystore-local.p12";
        string certPassword = "ks-password";
        
        // Load the certificate
        Pkcs12Store pk12 = new Pkcs12StoreBuilder().Build();
        pk12.Load(new FileStream(certPath, FileMode.Open, FileAccess.Read), certPassword.ToCharArray());
        string alias = null;
        foreach (var a in pk12.Aliases)
        {
            alias = (string) a;
            if (pk12.IsKeyEntry(alias))
                break;
        }

        ICipherParameters pk = pk12.GetKey(alias).Key;
        X509CertificateEntry[] ce = pk12.GetCertificateChain(alias);
        X509Certificate[] chain = new X509Certificate[ce.Length];
        for (int k = 0; k < ce.Length; k++)
        {
            chain[k] = ce[k].Certificate;
        }
        IX509Certificate[] certificateWrappers = new IX509Certificate[chain.Length];
        for (int i = 0; i < certificateWrappers.Length; ++i) {
            certificateWrappers[i] = new X509CertificateBC(chain[i]);
        }
        
        // Create a PdfSigner to apply the signature
        string newSignatureFieldName; 
        using PdfReader reader = new PdfReader(sourcePdf);
        PdfSigner signer = new PdfSigner(reader, new FileStream(signedPdf, FileMode.Create), new StampingProperties());
        {
            IExternalSignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256);
            var tsaClient = new TSAClientBouncyCastle("http://timestamp.digicert.com");
            signer.SignDetached(pks, chain, null, null, tsaClient, 0, PdfSigner.CryptoStandard.CADES);
            newSignatureFieldName = signer.GetFieldName();
        }
        Console.WriteLine("PDF signed successfully.");

        // Add LTV data
        using (PdfReader reader2 = new PdfReader(signedPdf))
        using (FileStream outputStream = new FileStream(signedLtvPdf, FileMode.Create))
        using (PdfDocument pdfDoc = new PdfDocument(reader2, new PdfWriter(outputStream), new StampingProperties().UseAppendMode()))
        {
            OCSPVerifier ocspVerifier = new OCSPVerifier(null, null);
            var ocspClient = new OcspClientBouncyCastle(ocspVerifier);
            var crlClient = new CrlClientOnline();

            LtvVerification ltvVerification = new LtvVerification(pdfDoc);
            ltvVerification.AddVerification(newSignatureFieldName, ocspClient, crlClient,
                LtvVerification.CertificateOption.WHOLE_CHAIN, LtvVerification.Level.OCSP_CRL, LtvVerification.CertificateInclusion.YES);
            ltvVerification.Merge();
        }

        Console.WriteLine("PDF LTV data added successfully.");
    }
}
