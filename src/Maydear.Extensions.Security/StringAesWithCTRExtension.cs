using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace System.Security.Cryptography
{
    /// <summary>
    /// AES测CTR模式
    /// </summary>
    public static class StringAesWithCTRExtension
    {
        #region AesCTREncrypt

        /// <summary>
        /// AES加密【CipherMode：CTR，Padding：NoPadding】
        /// </summary>
        /// <param name="data">待加密的明文字节码</param>
        /// <param name="key">加密公钥字节码</param>
        /// <param name="iv">加密向量字节码</param>
        /// <returns>返回AES加密后的字节码</returns>
        public static byte[] AesCTREncrypt(this byte[] data, byte[] key, byte[] iv)
        {
            var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            cipher.Init(true, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", key), iv));
            return cipher.DoFinal(data);
        }

        /// <summary>
        /// AES加密【CipherMode：CTR，Padding：NoPadding】
        /// </summary>
        /// <param name="data">待加密的明文</param>
        /// <param name="password">加密公钥</param>
        /// <returns>返回AES加密后的Base64编码的密文</returns>
        public static string AesCTREncryptToBase64(this string data, string password)
        {
            return AesCTREncryptToBase64(data?.ToBytes(), password?.ToBytes(), "0000000000000000".ToBytes());
        }


        /// <summary>
        /// AES加密【CipherMode：CTR，Padding：NoPadding】
        /// </summary>
        /// <param name="data">待加密的明文</param>
        /// <param name="password">加密公钥</param>
        /// <param name="ivStr">加密向量</param>
        /// <returns>返回AES加密后的Base64编码的密文</returns>
        public static string AesCTREncryptToBase64(this string data, string password, string ivStr)
        {
            return AesCTREncryptToBase64(data?.ToBytes(), password?.ToBytes(), ivStr?.ToBytes());
        }

        /// <summary>
        /// AES加密【Cipher：ECB，Padding：PKCS7】
        /// </summary>
        /// <param name="data">待加密的明文</param>
        /// <param name="keyBytes">加密公钥</param>
        /// <returns>返回AES加密后的Base64编码的密文</returns>
        public static string AesCTREncryptToBase64(this byte[] data, byte[] keyBytes, byte[] iv)
        {
            if (data.IsNullOrEmpty() || keyBytes.IsNullOrEmpty() || iv.IsNullOrEmpty())
            {
                return "";
            }
            return AesCTREncrypt(data, keyBytes, iv)?.ToBase64String();
        }

        /// <summary>
        /// AES加密【CipherMode：CTR，Padding：NoPadding】
        /// </summary>
        /// <param name="data">待加密的明文</param>
        /// <param name="password">加密公钥</param>
        /// <returns>返回AES加密后16进制字符编码的密文</returns>
        public static string AesCTREncryptToHex(this string data, string password)
        {
            return AesCTREncryptToHex(data?.ToBytes(), password?.ToBytes(), "0000000000000000".ToBytes());
        }


        /// <summary>
        /// AES加密【CipherMode：CTR，Padding：NoPadding】
        /// </summary>
        /// <param name="data">待加密的明文</param>
        /// <param name="password">加密公钥</param>
        /// <param name="ivStr">加密向量</param>
        /// <returns>返回AES加密后16进制字符编码的密文</returns>
        public static string AesCTREncryptToHex(this string data, string password, string ivStr)
        {
            return AesCTREncryptToHex(data?.ToBytes(), password?.ToBytes(), ivStr?.ToBytes());
        }

        /// <summary>
        /// AES加密【Cipher：ECB，Padding：PKCS7】
        /// </summary>
        /// <param name="data">待加密的明文</param>
        /// <param name="keyBytes">加密公钥</param>
        /// <returns>返回AES加密后16进制字符编码的密文</returns>
        public static string AesCTREncryptToHex(this byte[] data, byte[] keyBytes, byte[] iv)
        {
            if (data.IsNullOrEmpty() || keyBytes.IsNullOrEmpty() || iv.IsNullOrEmpty())
            {
                return "";
            }
            return AesCTREncrypt(data, keyBytes, iv)?.ToHexString();
        }


        #endregion

        #region AesCTRDecrypt

        /// <summary>
        /// AES解密【Cipher：CTR，Padding：NoPadding】
        /// </summary>
        /// <param name="data">待解密的密文字节码</param>
        /// <param name="keyBytes">加密公钥字节码</param>
        /// <param name="iv">加密向量字节码</param>
        /// <returns>返回AES解密后的字节码</returns>
        public static byte[] AesCTRDecrypt(this byte[] data, byte[] keyBytes, byte[] iv)
        {
            if (data.IsNullOrEmpty() || keyBytes.IsNullOrEmpty() || iv.IsNullOrEmpty())
            {
                return default;
            }

            var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            cipher.Init(false, new ParametersWithIV(ParameterUtilities.CreateKeyParameter("AES", keyBytes), iv));
            return cipher.DoFinal(data);
        }

        /// <summary>
        /// AES解密【Cipher：CTR，Padding：NoPadding】
        /// </summary>
        /// <param name="data">待解密的密文</param>
        /// <param name="keyBytes">加密公钥字节码</param>
        /// <param name="iv">加密向量字节码</param>
        /// <returns>返回一个由AesCTREncrypt加密而得到的明文</returns>
        public static string AesCTRDecryptFormBase64(this string data, byte[] keyBytes, byte[] iv)
        {
            byte[] toEncryptArray = Convert.FromBase64String(data);
            var resultArray = AesCTRDecrypt(toEncryptArray, keyBytes, iv);

            if (resultArray.IsNullOrEmpty())
            {
                return "";
            }
            return Encoding.UTF8.GetString(resultArray);
        }
        /// <summary>
        /// AES解密【Cipher：ECB，Padding：PKCS7】
        /// </summary>
        /// <param name="data">待解密的密文</param>
        /// <param name="password">加密公钥</param>
        /// <param name="ivStr">加密公钥</param>
        /// <returns>返回一个由AesEncrypt加密而得到的明文</returns>
        public static string AesCTRDecryptFormBase64(this string data, string password, string ivStr)
        {
            return AesCTRDecryptFormBase64(data, password?.ToBytes(), ivStr?.ToBytes());
        }

        /// <summary>
        /// AES解密【Cipher：ECB，Padding：PKCS7】
        /// </summary>
        /// <param name="data">待解密的密文</param>
        /// <param name="password">加密公钥</param>
        /// <param name="ivStr">加密公钥</param>
        /// <returns>返回一个由AesEncrypt加密而得到的明文</returns>
        public static string AesCTRDecryptFormBase64(this string data, string password)
        {
            return AesCTRDecryptFormBase64(data, password?.ToBytes(), "0000000000000000".ToBytes());
        }

        /// <summary>
        /// AES解密【Cipher：CTR，Padding：NoPadding】
        /// </summary>
        /// <param name="data">待解密的密文Hex编码</param>
        /// <param name="keyBytes">加密公钥字节码</param>
        /// <param name="iv">加密向量字节码</param>
        /// <returns>返回一个由AesCTREncrypt加密而得到的明文</returns>
        public static string AesCTRDecryptFormHex(this string data, byte[] keyBytes, byte[] iv)
        {
            byte[] toEncryptArray = new byte[data.Length / 2];

            for (int i = 0; i < data.Length; i += 2)
            {
                toEncryptArray[i / 2] = Convert.ToByte(data.Substring(i, 2), 16);
            }
            var resultArray = AesCTRDecrypt(toEncryptArray, keyBytes, iv);

            if (resultArray.IsNullOrEmpty())
            {
                return "";
            }
            return Encoding.UTF8.GetString(resultArray);
        }
        /// <summary>
        /// AES解密【Cipher：ECB，Padding：PKCS7】
        /// </summary>
        /// <param name="data">待解密的密文</param>
        /// <param name="password">加密公钥</param>
        /// <param name="ivStr">加密公钥</param>
        /// <returns>返回一个由AesEncrypt加密而得到的明文</returns>
        public static string AesCTRDecryptFormHex(this string data, string password, string ivStr)
        {
            return AesCTRDecryptFormHex(data, password?.ToBytes(), ivStr?.ToBytes());
        }

        /// <summary>
        /// AES解密【Cipher：ECB，Padding：PKCS7】
        /// </summary>
        /// <param name="data">待解密的密文</param>
        /// <param name="password">加密公钥</param>
        /// <param name="ivStr">加密公钥</param>
        /// <returns>返回一个由AesEncrypt加密而得到的明文</returns>
        public static string AesCTRDecryptFormHex(this string data, string password)
        {
            return AesCTRDecryptFormHex(data, password?.ToBytes(), "0000000000000000".ToBytes());
        }
        #endregion
    }
}
