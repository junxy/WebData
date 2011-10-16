using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using MvcApplication1.Entities;
using WebMatrix.Data;

namespace MvcApplication1.Controllers
{
    public class GalleryController : Controller
    {
        //
        // GET: /Gallery/

        public ActionResult Index()
        {
            var db = Database.Open("PhotoGallery");
            
            var galleries = db.Query(@"SELECT Galleries.Id, Galleries.Name, COUNT(Photos.Id) AS PhotoCount
                               FROM Galleries LEFT OUTER JOIN Photos ON Galleries.Id = Photos.GalleryId
                               GROUP BY Galleries.Id, Galleries.Name").ToList<Gallery>();


            //    new List<Gallery>() { 
            //    new Gallery()
            //    {
            //        Id=1,
            //        Name="我",
            //        PhotoCount = 0
            //    }
            //};

            return View(galleries);
        }

        public ActionResult View(int id)
        {
            return View();
        }


        public ActionResult Thumbnail(int id)
        {
            return File("~/Images/gallery-empty.png", "image/png");
        }

        public ActionResult New()
        {
            return View();
        }

        [HttpPost]
        public ActionResult New(Gallery gallery)
        {
            if (ModelState.IsValid)
            {
                return Content("ok");
            }
            return View();
        }

        [HttpPost]
        public ActionResult Upload()
        {
            return Content("ok");
        }

    }
}
