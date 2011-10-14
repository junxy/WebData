namespace WebMatrix.Data {
    using System.Data.Common;

    internal interface IDbProviderFactory {
        DbConnection CreateConnection(string connectionString);
    }
}
