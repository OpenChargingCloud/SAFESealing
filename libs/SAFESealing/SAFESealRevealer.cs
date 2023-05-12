namespace SAFESealing
{
    public class SAFESealRevealer
    {

        public Boolean UseECDHE { get; }

        public SAFESealRevealer(Boolean UseECDHE = false)
        {
            this.UseECDHE = UseECDHE;
        }

    }
}