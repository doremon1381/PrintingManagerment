using Microsoft.AspNetCore.Identity;
#if DbServer
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;
#endif

namespace PrMDbModels
{
#if DbServer
    [Table("PrMUserTokens")]
    [PrimaryKey(nameof(Id))]
#endif
    public class PrMUserToken: IdentityUserToken<int>, IDbTable
    {
#if DbServer
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
#endif
        public int Id { get; set; }
        public PrMUser User { get; set; }

    }
}
