using Org.BouncyCastle.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SAFESealing
{
    public class IvParameterSpec
    {

        public Byte[] iv { get; }

        public IvParameterSpec(Byte[] iv)
        {
            this.iv = iv;
        }

    }

}
