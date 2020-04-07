using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace System.Security.Cryptography
{
    /// <summary>
    /// 中华人民共和国政府采用的密码散列函数标准扩展
    /// </summary>
    public static class StringChinaSecurityExtension
    {
        #region SM3

        /// <summary>
        /// SM3加密
        /// <para>
        /// SM3是中华人民共和国政府采用的一种密码散列函数标准，由国家密码管理局于2010年12月17日发布。相关标准为“GM/T 0004-2012 《SM3密码杂凑算法》”。
        /// 在商用密码体系中，SM3主要用于数字签名及验证、消息认证码生成及验证、随机数生成等，其算法公开。据国家密码管理局表示，其安全性及效率与SHA-256相当。
        /// </para>
        /// </summary>
        /// <param name="data">待加密的数据</param>
        /// <returns>返回SM3加密后的二进制字节数组</returns>
        public static byte[] SM3(this string data)
        {
            if (string.IsNullOrEmpty(data))
            {
                return null;
            }
            var digest = new SM3Digest();
            var bytes = Encoding.UTF8.GetBytes(data);
            digest.BlockUpdate(bytes, 0, bytes.Length);
            return DigestUtilities.DoFinal(digest);
        }


        /// <summary>
        /// SM3加密
        /// <para>
        /// SM3是中华人民共和国政府采用的一种密码散列函数标准，由国家密码管理局于2010年12月17日发布。相关标准为“GM/T 0004-2012 《SM3密码杂凑算法》”。
        /// 在商用密码体系中，SM3主要用于数字签名及验证、消息认证码生成及验证、随机数生成等，其算法公开。据国家密码管理局表示，其安全性及效率与SHA-256相当。
        /// </para>
        /// </summary>
        /// <param name="data">待加密的数据</param>
        /// <returns>返回SHA256加密后的Base64编码密文</returns>
        public static string SM3ToBase64(this string data)
        {
            if (string.IsNullOrEmpty(data))
            {
                return string.Empty;
            }
            byte[] inArray = data.SM3();
            return inArray.ToBase64String();
        }

        /// <summary>
        /// SM3加密
        /// <para>
        /// SM3是中华人民共和国政府采用的一种密码散列函数标准，由国家密码管理局于2010年12月17日发布。相关标准为“GM/T 0004-2012 《SM3密码杂凑算法》”。
        /// 在商用密码体系中，SM3主要用于数字签名及验证、消息认证码生成及验证、随机数生成等，其算法公开。据国家密码管理局表示，其安全性及效率与SHA-256相当。
        /// </para>
        /// </summary>
        /// <param name="data">待加密的数据</param>
        /// <returns>返回SHA256加密后的十六进制格式密文</returns>
        public static string SM3ToHex(this string data)
        {
            if (string.IsNullOrEmpty(data))
            {
                return string.Empty;
            }
            byte[] inArray = data.SM3();
            return inArray.ToHexString();
        }

        #endregion
    }
}
