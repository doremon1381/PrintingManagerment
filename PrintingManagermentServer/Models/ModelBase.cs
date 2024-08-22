using System.ComponentModel.DataAnnotations.Schema;

namespace PrintingManagermentServer.Models
{
    public class ModelBase : IDbTable
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
    }

    // particular use for checking if an instance of entity of dataset can be assigned to IDbTable's instance
    public interface IDbTable
    {
    }
}
