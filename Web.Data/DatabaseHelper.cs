using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data;

namespace WebMatrix.Data
{
    public static class DatabaseHelper
    {

        public static IList<T> ToList<T>(this DataTable dt)
        {
            if (dt == null)
                throw new ArgumentNullException("dt");

            var list = new List<T>(dt.Rows.Count);            
            var properties = typeof(T).GetProperties();
            var colNames = dt.Columns;

            for (int i = 0; i < dt.Rows.Count; i++)
            {
                var dr = dt.Rows[i];
                

                
            }
            

            return list;

        }


    }
}
