using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace Maydear.Extensions.Security
{
    internal static class SecurityExtension
    {
        #region Encrypt

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="data">待加密的字节码</param>
        /// <param name="cipherAlgorithm">密码算法</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="cipherParameters">加密参数</param>
        /// <returns>返回加密后的字节码</returns>
        internal static byte[] Encrypt(byte[] data, CipherAlgorithm cipherAlgorithm, CipherMode cipherMode, CipherPadding cipherPadding, ICipherParameters cipherParameters)
        {
            if(data.IsNullOrEmpty())
            {
                return default;
            }

            var cipher = CipherUtilities.GetCipher($"{cipherAlgorithm}/{cipherMode}/{cipherPadding}");
            cipher.Init(true, cipherParameters);
            return cipher.DoFinal(data);
        }

        #endregion

        #region Decrypt

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="data">待解密的字节码</param>
        /// <param name="cipherAlgorithm">密码算法</param>
        /// <param name="cipherMode">密码模式</param>
        /// <param name="cipherPadding">填充方式</param>
        /// <param name="cipherParameters">加密参数</param>
        /// <returns>返回AES解密后的字节码</returns>
        public static byte[] Decrypt(byte[] data, CipherAlgorithm cipherAlgorithm, CipherMode cipherMode, CipherPadding cipherPadding, ICipherParameters cipherParameters)
        {
            if (data.IsNullOrEmpty())
            {
                return default;
            }

            var cipher = CipherUtilities.GetCipher($"{cipherAlgorithm}/{cipherMode}/{cipherPadding}");
            cipher.Init(false, cipherParameters);
            return cipher.DoFinal(data);
        }

        #endregion
    }
}
