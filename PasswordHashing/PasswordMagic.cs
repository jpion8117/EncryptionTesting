using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text.Json;

namespace PasswordHashing
{
    internal class PasswordMagic
    {
        private string _unencryptedPw = "";
        private string _passwordHash = "";
        static private UnicodeEncoding _encoding = new UnicodeEncoding();
        
        public PasswordMagic(string unencryptedPw)
        {
            UnencryptedPw = unencryptedPw;
        }
        public string PasswordHash
        {
            get { return _passwordHash; }
        }
        public string UnencryptedPw
        {
            set
            {
                _unencryptedPw = value;

                using (SHA512 shaM = SHA512.Create())
                {
                    var toEncrypt = Encoding.Unicode.GetBytes(_unencryptedPw);
                    var hash = shaM.ComputeHash(toEncrypt);

                    foreach (byte b in hash)
                    {
                        _passwordHash += String.Format("{0:x2}", b);
                    }
                }
            }
            get => _unencryptedPw;
        }
        public static void GenerateKey(out string key, out string initializationVector)
        {
            using (Aes aesAlgorithm = Aes.Create())
            {
                key = Convert.ToBase64String(aesAlgorithm.Key);
                initializationVector = Convert.ToBase64String(aesAlgorithm.IV);
            }
        }

        static public string EncryptAES(string plaintext, string key, string initializationVector)
        {
            string cyphertext = "";

            using (Aes aesAlgorithm = Aes.Create())
            {
                aesAlgorithm.Key = Convert.FromBase64String(key);
                aesAlgorithm.IV = Convert.FromBase64String(initializationVector);
                ICryptoTransform encryptor = aesAlgorithm.CreateEncryptor();
                
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cryptostream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter writer = new StreamWriter(cryptostream))
                        {
                            writer.Write(plaintext);
                        }

                        cyphertext = Convert.ToBase64String(ms.ToArray());
                    }
                }
            }

            return cyphertext;
        }
        static public string DecryptAES(string cyphertext, string key, string initializationVector)
        {
            string plaintext = "";

            using (Aes aesAlgorithm = Aes.Create())
            {
                aesAlgorithm.Key = Convert.FromBase64String(key);
                aesAlgorithm.IV = Convert.FromBase64String(initializationVector);
                ICryptoTransform decryptor = aesAlgorithm.CreateDecryptor();

                using (MemoryStream memory = new MemoryStream(Convert.FromBase64String(cyphertext)))
                {
                    using (CryptoStream cryptostream = new CryptoStream(memory, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(cryptostream))
                        {
                            plaintext = reader.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        //static public string EncryptRSA(string plaintext, string key)
        //{
        //    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        //    {
        //        var jsonOptions = new JsonSerializerOptions();
        //        jsonOptions.IncludeFields = true;

        //        RSAParameters param = JsonSerializer.Deserialize<RSAParameters>(key, jsonOptions);
        //        rsa.ImportParameters(param);

        //        var encryptedText = rsa.Encrypt(_encoding.GetBytes(plaintext), false);

        //        return _encoding.GetString(encryptedText);
        //    }
        //}
        //static public string DecryptRSA(string encryptedText, string key)
        //{
        //    using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        //    {
        //        var jsonOptions = new JsonSerializerOptions();
        //        jsonOptions.IncludeFields = true;

        //        RSAParameters param = JsonSerializer.Deserialize<RSAParameters>(key, jsonOptions);

        //        rsa.ImportParameters(param);

        //        var plainText = rsa.Decrypt(_encoding.GetBytes(encryptedText), false);

        //        return _encoding.GetString(plainText);
        //    }
        //}
        public bool Validate(string pwHash)
        {
            if (pwHash == PasswordHash)
                return true;
            else
                return false;
        }
    }
}
