using System;

namespace MvcApplication1.Entities
{
    public class Comment
    {
        public int Id { get; set; }

        public int PhotoId { get; set; }

        public int UserId { get; set; }

        public DateTime CommentDate { get; set; }

        public string CommentText { get; set; }

    }
}
