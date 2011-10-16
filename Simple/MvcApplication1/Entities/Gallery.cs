using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace MvcApplication1.Entities
{
    /// <summary>
    /// 照片库
    /// </summary>
    public class Gallery
    {
        public int Id { get; set; }

        [DisplayName("名称")]
        [Required(ErrorMessage = "您必须指定库名称")]
        public string Name { get; set; }

        public int PhotoCount { get; set; }
    }
}