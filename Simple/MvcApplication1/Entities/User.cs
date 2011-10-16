using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace MvcApplication1.Entities
{
    public class User
    {
        [DisplayName("显示名称")]
        [DataType(DataType.Text)]
        public string DisplayName { get; set; }

        [DisplayName("个人简介")]
        [DataType(DataType.MultilineText)]
        public string Bio { get; set; }

    }
}
