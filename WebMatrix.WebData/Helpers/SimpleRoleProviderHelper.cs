using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data;

namespace WebMatrix.WebData.Helpers
{
    public static class SimpleRoleProviderHelper
    {
        public static int Count(this DataTable dt ){
            return dt != null && dt.Rows.Count > 0 ? dt.Rows.Count : 0;
        }


    }
}
