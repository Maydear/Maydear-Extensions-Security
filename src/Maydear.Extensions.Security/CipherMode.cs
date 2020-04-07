using System;
using System.Collections.Generic;
using System.Text;

namespace Maydear.Extensions.Security
{
    /// <summary>
    /// 密码模式
    /// </summary>
    public enum CipherMode
    {
        ECB,
        NONE,
        CBC,
        CCM,
        CFB,
        CTR,
        CTS,
        EAX,
        GCM,
        GOFB,
        OCB,
        OFB,
        OPENPGPCFB,
        SIC
    }
}
