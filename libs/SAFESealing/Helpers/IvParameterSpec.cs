
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
