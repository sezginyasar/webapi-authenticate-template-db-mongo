namespace webapiV2.Database
{
    public class DatabaseSettings : IDatabaseSettings
    {
        public string ConnectionString { get; set; } = null!;
        public string DatabaseName { get; set; } = null!;
        // public string CollectionName { get; set; } = null!;
    }
}