namespace webapiV2.Database
{
    public interface IDatabaseSettings
    {
        string ConnectionString { get; set; }
        string DatabaseName { get; set; }
        // string CollectionName {get; set;}
    }
}