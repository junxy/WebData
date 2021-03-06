﻿using System;
using System.Data.Common;

namespace WebMatrix.Data {
    public class ConnectionEventArgs : EventArgs {
        public ConnectionEventArgs(DbConnection connection) {
            Connection = connection;
        }
        public DbConnection Connection { get; private set; }
    }
}
