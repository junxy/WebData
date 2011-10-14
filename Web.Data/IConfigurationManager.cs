namespace WebMatrix.Data {
    using System.Collections.Generic;

    internal interface IConfigurationManager {        
        IConnectionConfiguration GetConnection(string name);
        IDictionary<string, string> AppSettings { get; }
    }
}
