using Microsoft.Extensions.Configuration;
using Org.BouncyCastle.Crypto.Parameters;
using PrMServerUltilities;
using System.Security.Cryptography;
using System.Text;

namespace PrintingManagermentServer.Services
{
    public static class TokenExtensions
    {
        public static bool VerifySignature(string jwt, string key)
        {
            string[] parts = jwt.Split(".".ToCharArray());
            var header = parts[0];
            var payload = parts[1];
            var signature = parts[2];//Base64UrlEncoded signature from the token

            byte[] bytesToSign = Encoding.UTF8.GetBytes(string.Join(".", header, payload));

            // TODO: will change how to get this part later
            byte[] secret = Encoding.UTF8.GetBytes(key);

            var alg = new HMACSHA256(secret);
            var hash = alg.ComputeHash(bytesToSign);

            var computedSignature = RNGCryptoServicesUltilities.Base64urlencodeNoPadding(hash);

            return signature.Equals(computedSignature);
        }

        /// <summary>
        /// TODO: will learn how to use in future
        /// </summary>
        /// <param name="idToken"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static bool VerifyRsa256Signature(string idToken, string publicKey)
        {
            string[] parts = idToken.Split('.');
            string header = parts[0];
            string payload = parts[1];
            byte[] crypto = RNGCryptoServicesUltilities.Base64UrlDecode(parts[2]);

            var keyBytes = Convert.FromBase64String(publicKey);

            //var rsaKey = Org.BouncyCastle.Asn1.X509.RsaPublicKeyStructure.GetInstance(publicKey);

            //var pubkeyParams = new RsaKeyParameters(false, rsaKey.Modulus, rsaKey.PublicExponent);

            var rsaKey = Org.BouncyCastle.Asn1.X509.RsaPublicKeyStructure.GetInstance(publicKey);

            var pubkeyParams = new RsaKeyParameters(false, rsaKey.Modulus, rsaKey.PublicExponent);

            //AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(keyBytes);
            //AsymmetricKeyParameter asymmetricKeyParameter = (AsymmetricCipherKeyPair)new PemReader(reader).ReadObject();
            //RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            RSAParameters rsaParameters = new RSAParameters();
            rsaParameters.Modulus = pubkeyParams.Modulus.ToByteArrayUnsigned();
            rsaParameters.Exponent = pubkeyParams.Exponent.ToByteArrayUnsigned();
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);

            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");

            return rsaDeformatter.VerifySignature(hash, Convert.FromBase64String(parts[2]));
        }
    }
}
