using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace Maydear.Extensions.Security
{
    /// <summary>
    /// RAS加密/解密扩展
    /// </summary>
    public static class RsaSecurityExtension
    {
        #region RsaEncrypt

        /// <summary>
        /// Rsa加密
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="isPublicKey">是否公钥</param>
        /// <param name="base64Key">BASE64编码的公钥</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaEncrypt(this byte[] data, bool isPublicKey, string base64Key, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            ICipherParameters cipherParameters;
            if (isPublicKey)
            {
                cipherParameters = RSAUtilities.GetKeyParameterFormPublicKey(base64Key);
            }
            else
            {
                cipherParameters = RSAUtilities.GetKeyParameterFormPrivateKey(base64Key);
            }
            return SecurityExtension.Encrypt(data, CipherAlgorithm.RSA, cipherMode, cipherPadding, cipherParameters);
        }

        /// <summary>
        /// 使用公钥Rsa加密
        /// <para>
        /// 如果PKCS#8格式的公钥则使用 <see cref="RsaEncryptByPublicKey"/>
        /// </para>
        /// <para>
        /// 如果PKCS#1格式的公钥则使用 <see cref="RsaEncryptByAsn1PublicKey"/>
        /// </para>
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="publicKey">PKCS#8格式的公钥（BASE64编码）</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaEncryptByPublicKey(this byte[] data, string publicKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaEncrypt(data, true, publicKey, cipherMode, cipherPadding);
        }

        /// <summary>
        /// 使用公钥Rsa解密
        /// <para>
        /// 如果PKCS#8格式的公钥则使用 <see cref="RsaEncryptByPublicKey"/>
        /// </para>
        /// <para>
        /// 如果PKCS#1格式的公钥则使用 <see cref="RsaEncryptByAsn1PublicKey"/>
        /// </para>
        /// </summary>
        /// <param name="data">待解密的字节码</param>
        /// <param name="publicKey">PKCS#1的BASE64编码的公钥（BASE64编码）</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaEncryptByAsn1PublicKey(this byte[] data, string publicKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            var cipherParameters = RSAUtilities.GetPublicKeyParameterFormAsn1PublicKey(publicKey);
            return SecurityExtension.Encrypt(data, CipherAlgorithm.RSA, cipherMode, cipherPadding, cipherParameters);
        }
        /// <summary>
        /// 使用私钥Rsa加密
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="privateKey">BASE64编码的私钥</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaEncryptByPrivateKey(this byte[] data, string privateKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaEncrypt(data, false, privateKey, cipherMode, cipherPadding);
        }
        
        /// <summary>
        /// Rsa加密并返回base64编码的字符
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="isPublicKey">是否公钥</param>
        /// <param name="base64Key">BASE64编码的公钥</param>
        /// <returns>返回Rsa加密后的base64编码的字符</returns>
        public static string RsaEncryptToBase64(this byte[] data, bool isPublicKey, string base64Key, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaEncrypt(data, isPublicKey, base64Key, cipherMode, cipherPadding)?.ToBase64String();
        }

        /// <summary>
        /// 使用私钥Rsa加密并返回base64编码的字符
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="privateKey">BASE64编码的私钥</param>
        /// <returns>返回Rsa加密后的base64编码的字符</returns>
        public static string RsaEncryptByPrivateKeyToBase64(this byte[] data,string privateKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaEncryptByPrivateKey(data, privateKey, cipherMode, cipherPadding)?.ToBase64String();
        }


        /// <summary>
        /// 使用私钥Rsa加密并返回base64编码的字符
        /// <para>
        /// 如果PKCS#1格式的公钥则使用 <see cref="RsaEncryptByAsn1PublicKeyToBase64"/>
        /// </para>
        /// <para>
        /// 如果PKCS#8格式的公钥则使用 <see cref="RsaEncryptByPublicKeyToBase64"/>
        /// </para>
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="publicKey">PKCS#8格式的公钥</param>
        /// <returns>返回Rsa加密后的base64编码的字符</returns>
        public static string RsaEncryptByPublicKeyToBase64(this byte[] data, string publicKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaEncryptByPublicKey(data, publicKey, cipherMode, cipherPadding)?.ToBase64String();
        }
        /// <summary>
        /// 使用私钥Rsa加密并返回base64编码的字符。
        /// <para>
        /// 如果PKCS#1格式的公钥则使用 <see cref="RsaEncryptByAsn1PublicKeyToBase64"/>
        /// </para>
        /// <para>
        /// 如果PKCS#8格式的公钥则使用 <see cref="RsaEncryptByPublicKeyToBase64"/>
        /// </para>
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="publicKey">PKCS#1的BASE64编码的公钥</param>
        /// <returns>返回Rsa加密后的base64编码的字符</returns>
        public static string RsaEncryptByAsn1PublicKeyToBase64(this byte[] data, string publicKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaEncryptByAsn1PublicKey(data, publicKey, cipherMode, cipherPadding)?.ToBase64String();
        }

        /// <summary>
        /// Rsa加密并返回base64编码的字符
        /// </summary>
        /// <param name="data">待加密的字符串</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="isPublicKey">是否公钥</param>
        /// <param name="base64Key">BASE64编码的公钥</param>
        /// <returns>返回Rsa加密后的base64编码的字符</returns>
        public static string RsaEncryptToBase64(this string data, bool isPublicKey, string base64Key, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaEncryptToBase64(data?.ToBytes(), isPublicKey, base64Key, cipherMode, cipherPadding);
        }

        /// <summary>
        /// Rsa加密并返回十六进制的字符
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="isPublicKey">是否公钥</param>
        /// <param name="base64Key">BASE64编码的公钥</param>
        /// <returns>返回Rsa加密后的十六进制的字符</returns>
        public static string RsaEncryptToHex(this byte[] data, bool isPublicKey, string base64Key, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaEncrypt(data, isPublicKey, base64Key, cipherMode, cipherPadding)?.ToHexString();
        }

        /// <summary>
        /// Rsa加密并返回十六进制的字符
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="isPublicKey">是否公钥</param>
        /// <param name="base64Key">BASE64编码的公钥</param>
        /// <returns>返回Rsa加密后的十六进制的字符</returns>
        public static string RsaEncryptToHex(this string data, bool isPublicKey, string base64Key, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaEncryptToHex(data?.ToBytes(), isPublicKey, base64Key, cipherMode, cipherPadding);
        }

        /// <summary>
        /// 使用私钥Rsa加密并返回十六进制的字符
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="privateKey">BASE64编码的私钥</param>
        /// <returns>返回Rsa加密后的十六进制的字符</returns>
        public static string RsaEncryptByPrivateKeyToHex(this byte[] data, string privateKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaEncryptByPrivateKey(data, privateKey, cipherMode, cipherPadding)?.ToHexString();
        }

        /// <summary>
        /// 使用私钥Rsa加密并返回base64编码的字符
        /// <para>
        /// 如果PKCS#1格式的公钥则使用 <see cref="RsaEncryptByAsn1PublicKeyToHex"/>
        /// </para>
        /// <para>
        /// 如果PKCS#8格式的公钥则使用 <see cref="RsaEncryptByPublicKeyToHex"/>
        /// </para>
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="publicKey">BASE64编码的公钥</param>
        /// <returns>返回Rsa加密后的十六进制的字符</returns>
        public static string RsaEncryptByPublicKeyToHex(this byte[] data, string publicKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaEncryptByPublicKey(data, publicKey, cipherMode, cipherPadding)?.ToHexString();
        }

        /// <summary>
        /// 使用私钥Rsa加密并返回base64编码的字符
        /// <para>
        /// 如果PKCS#1格式的公钥则使用 <see cref="RsaEncryptByAsn1PublicKeyToHex"/>
        /// </para>
        /// <para>
        /// 如果PKCS#8格式的公钥则使用 <see cref="RsaEncryptByPublicKeyToHex"/>
        /// </para>
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="publicKey">BASE64编码的公钥</param>
        /// <returns>返回Rsa加密后的十六进制的字符</returns>
        public static string RsaEncryptByAsn1PublicKeyToHex(this byte[] data, string publicKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaEncryptByAsn1PublicKey(data, publicKey, cipherMode, cipherPadding)?.ToHexString();
        }
        #endregion

        #region RsaDecrypt

        /// <summary>
        /// Rsa解密
        /// </summary>
        /// <param name="data">待解密的字节码</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="isPublicKey">是否公钥</param>
        /// <param name="base64Key">BASE64编码的公钥</param>
        /// <returns>返回Rsa解密后的字节码</returns>
        public static byte[] RsaDecrypt(this byte[] data, bool isPublicKey, string base64Key, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            ICipherParameters cipherParameters;
            if (isPublicKey)
            {
                cipherParameters = RSAUtilities.GetKeyParameterFormPrivateKey(base64Key);
            }
            else
            {
                cipherParameters = RSAUtilities.GetKeyParameterFormPublicKey(base64Key);
            }
            return SecurityExtension.Encrypt(data, CipherAlgorithm.RSA, cipherMode, cipherPadding, cipherParameters);
        }

        /// <summary>
        /// 使用公钥Rsa解密
        /// <para>
        /// 如果PKCS#1格式的公钥则使用 <see cref="RsaDecryptByAsn1PublicKey"/>
        /// </para>
        /// <para>
        /// 如果PKCS#8格式的公钥则使用 <see cref="RsaDecryptByPublicKey"/>
        /// </para>
        /// </summary>
        /// <param name="data">待解密的字节码</param>
        /// <param name="publicKey">PKCS#8的 BASE64编码的公钥</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaDecryptByPublicKey(this byte[] data, string publicKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaDecrypt(data, true, publicKey, cipherMode, cipherPadding);
        }

        /// <summary>
        /// 使用公钥Rsa解密
        /// </summary>
        /// <param name="data">待解密的字节码</param>
        /// <param name="publicKey">PKCS#1的BASE64编码的公钥</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaDecryptByAsn1PublicKey(this byte[] data, string publicKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            var cipherParameters = RSAUtilities.GetPublicKeyParameterFormAsn1PublicKey(publicKey);
            return SecurityExtension.Decrypt(data, CipherAlgorithm.RSA, cipherMode, cipherPadding, cipherParameters);
        }

        /// <summary>
        /// 使用私钥Rsa解密
        /// </summary>
        /// <param name="data">待解密的字节码</param>
        /// <param name="privateKey">BASE64编码的私钥</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaDecryptByPrivateKey(this byte[] data, string privateKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            return RsaDecrypt(data, false, privateKey, cipherMode, cipherPadding);
        }

        /// <summary>
        /// 使用公钥Rsa解密
        /// <para>
        /// 如果PKCS#1格式的公钥则使用 <see cref="RsaDecryptByAsn1PublicKey"/>
        /// </para>
        /// <para>
        /// 如果PKCS#8格式的公钥则使用 <see cref="RsaDecryptByPublicKey"/>
        /// </para>
        /// </summary>
        /// <param name="data">待解密的字节码</param>
        /// <param name="publicKey">PKCS#8的 BASE64编码的公钥</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaDecryptByPublicKeyFromBase64(this string data, string publicKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            byte[] toEncryptArray = Convert.FromBase64String(data);
            return RsaDecrypt(toEncryptArray, true, publicKey, cipherMode, cipherPadding);
        }

        /// <summary>
        /// 使用公钥Rsa解密
        /// </summary>
        /// <param name="data">待解密的字节码</param>
        /// <param name="publicKey">PKCS#1的BASE64编码的公钥</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaDecryptByAsn1PublicKeyFromBase64(this string data, string publicKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            byte[] toEncryptArray = Convert.FromBase64String(data);
            return RsaDecryptByAsn1PublicKey(toEncryptArray, publicKey, cipherMode, cipherPadding);
        }

        /// <summary>
        /// 使用私钥Rsa解密
        /// </summary>
        /// <param name="data">待解密的字节码</param>
        /// <param name="privateKey">BASE64编码的私钥</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaDecryptByPrivateKeyFromBase64(this string data, string privateKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            byte[] toEncryptArray = Convert.FromBase64String(data);
            return RsaDecrypt(toEncryptArray, false, privateKey, cipherMode, cipherPadding);
        }

        /// <summary>
        /// 使用公钥Rsa解密
        /// <para>
        /// 如果PKCS#1格式的公钥则使用 <see cref="RsaDecryptByAsn1PublicKeyFromHex"/>
        /// </para>
        /// <para>
        /// 如果PKCS#8格式的公钥则使用 <see cref="RsaDecryptByPublicKeyFromHex"/>
        /// </para>
        /// </summary>
        /// <param name="data">待解密的字节码</param>
        /// <param name="publicKey">PKCS#8的 BASE64编码的公钥</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaDecryptByPublicKeyFromHex(this string data, string publicKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            byte[] toEncryptArray = new byte[data.Length / 2];

            for (int i = 0; i < data.Length; i += 2)
            {
                toEncryptArray[i / 2] = Convert.ToByte(data.Substring(i, 2), 16);
            }
            return RsaDecryptByPublicKey(toEncryptArray, publicKey, cipherMode, cipherPadding);
        }

        /// <summary>
        /// 使用公钥Rsa解密
        /// </summary>
        /// <param name="data">待解密的字节码</param>
        /// <param name="publicKey">PKCS#1的BASE64编码的公钥</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaDecryptByAsn1PublicKeyFromHex(this string data, string publicKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            byte[] toEncryptArray = new byte[data.Length / 2];

            for (int i = 0; i < data.Length; i += 2)
            {
                toEncryptArray[i / 2] = Convert.ToByte(data.Substring(i, 2), 16);
            }
            return RsaDecryptByAsn1PublicKey(toEncryptArray, publicKey, cipherMode, cipherPadding);
        }

        /// <summary>
        /// 使用私钥Rsa解密
        /// </summary>
        /// <param name="data">待解密的字节码</param>
        /// <param name="privateKey">BASE64编码的私钥</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <returns>返回Rsa加密后的字节码</returns>
        public static byte[] RsaDecryptByPrivateKeyFromHex(this string data, string privateKey, CipherMode cipherMode, CipherPadding cipherPadding)
        {
            byte[] toEncryptArray = new byte[data.Length / 2];

            for (int i = 0; i < data.Length; i += 2)
            {
                toEncryptArray[i / 2] = Convert.ToByte(data.Substring(i, 2), 16);
            }
            return RsaDecryptByPrivateKey(toEncryptArray, privateKey, cipherMode, cipherPadding);
        }
        
        #endregion
    }
}
