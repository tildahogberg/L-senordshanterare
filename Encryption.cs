using System;
using System.IO;
using System.Security.Cryptography;

namespace Lösenordshanterare
{
    internal class Encryption : IDisposable
    {
        Aes aes;
        private bool disposedValue;


        static public byte[] GenerateSecretKey()
        {
            byte[] secretKey = new byte[8];
            using RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(secretKey);
            return secretKey;
        }

        static public byte[] GenerateIV()
        {
            Aes aes = Aes.Create();
            return aes.IV;
        }


        public Encryption(string masterpwd, byte[] secretkey)
        {
            aes = Aes.Create();
            aes.Key = CreateKey(masterpwd, secretkey);
        }


        static public byte[] CreateKey(string masterpwd, byte[] secretkey)
        {
            using Rfc2898DeriveBytes rfc = new Rfc2898DeriveBytes(masterpwd, secretkey, 1000, HashAlgorithmName.SHA512);
            return rfc.GetBytes(16);
        }

        static public string Decrypt(byte[] EncryptedVault, byte[] vaultKey, byte[] IV)
        {
            if (EncryptedVault == null || EncryptedVault.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (vaultKey == null || vaultKey.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = vaultKey;
                aesAlg.IV = IV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(EncryptedVault))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        static public byte[] Encrypt(string serializedVault, byte[] vaultKey, byte[] IV)
        {
            if (serializedVault == null || serializedVault.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (vaultKey == null || vaultKey.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = vaultKey;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(serializedVault);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }

        public void Dispose()
        {
            if (!disposedValue)
            {
                aes?.Dispose();
                disposedValue = true;
                GC.SuppressFinalize(this);
            }
        }
    }
}


