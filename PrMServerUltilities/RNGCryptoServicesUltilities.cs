using System.Security.Cryptography;
using System.Text;

namespace PrMServerUltilities
{

    /// <summary>
    /// TODO: will delete
    /// </summary>
    public static class RNGCryptoServicesUltilities
    {
        // rfc 7636 impliment
        public static void GetMitigateAttackMethod()
        {
            string status = RandomStringGeneratingWithLength(32);
            string code_verifier = RandomStringGeneratingWithLength(32);
            string code_challenge = Base64UrlEncodeNoPadding(code_verifier.WithSHA265());
            string code_challenge_method = "S256";
        }

        public static string RandomStringGeneratingWithLength(int length)
        {
            RNGCryptoServiceProvider strGenerator = new RNGCryptoServiceProvider();
            byte[] arr = new byte[length];
            strGenerator.GetBytes(arr, 0, length);

            return Base64UrlEncodeNoPadding(arr);
        }

        private static string Base64UrlEncodeNoPadding(byte[] str)
        {
            string base64 = Convert.ToBase64String(str);

            // convert base64 to base64url
            base64.Replace("+", "-");
            base64.Replace("/", "_");

            // strip padding
            base64.Replace("=", "");

            return base64;
        }

        private static byte[] WithSHA265(this string str)
        {
            byte[] newByteArr = Encoding.ASCII.GetBytes(str);
            SHA256Managed sha256 = new SHA256Managed();
            return sha256.ComputeHash(newByteArr);
        }

        public static string GetStringWithSHA256(this string str)
        {
            byte[] newByteArr = Encoding.ASCII.GetBytes(str);
            SHA256Managed sha256 = new SHA256Managed();
            var hashBytes = sha256.ComputeHash(newByteArr);

            StringBuilder sb = new StringBuilder();

            foreach (var b in hashBytes)
            {
                sb.Append(b.ToString());
            }

            return sb.ToString();
        }

        /// <summary>
        /// Returns URI-safe data with a given input length.
        /// </summary>
        /// <param name="length">Input length (nb. output will be longer)</param>
        /// <returns></returns>
        public static string RandomDataBase64url(uint length)
        {
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[length];
            rng.GetBytes(bytes);
            return base64urlencodeNoPadding(bytes);
        }


        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static string base64urlencodeNoPadding(byte[] buffer)
        {
            string base64 = Convert.ToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }
    }
}
