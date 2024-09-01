using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrMDbModels
{

    [Table("TokenRequestHandlers")]
    [PrimaryKey(nameof(Id))]
    public class TokenRequestHandler : ModelBase
    {
        //public int? LoginSessionId { get; set; }
        public TokenRequestSession? TokenRequestSession { get; set; }

        public int? UserId { get; set; }
        public PrMUser User { get; set; }

        //public int? TokenResponseId { get; set; }
        public TokenResponse? TokenResponse { get; set; }

        public TokenExternal? TokenExternal { get; set; }

        //public 
    }
}
