using System;

namespace MvcApplication1.Entities
{
    /// <summary>
    /// 照片
    /// </summary>
    public class Photo
    {
        public int Id { get; set; }

        public int GalleryId { get; set; }

        public int UserId { get; set; }

        public string ContentType { get; set; }

        public string Description { get; set; }

        public byte[] FileContents { get; set; }

        public string FileExtension { get; set; }

        public int FileSize { get; set; }

        public string FileTitle { get; set; }

        public byte[] ModifyedFileContents { get; set; }

        public DateTime UploadDate { get; set; }
    }
}