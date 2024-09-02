using System.ComponentModel.DataAnnotations.Schema;

namespace PrMDbModels
{
    public class ModelBase: IDbTable
    {
#if IdentityServer
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
#endif
        public int Id { get; set; }
    }
}
