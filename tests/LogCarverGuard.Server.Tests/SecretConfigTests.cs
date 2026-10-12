using LogCarverGuard.Server;

using Microsoft.Extensions.Configuration;

namespace LogCarverGuard.Server.Tests;

public sealed class SecretConfigTests : IDisposable
{
    private readonly string _secretFilePath = Path.Combine(Path.GetTempPath(), $"logcarverguard-secret-test-{Guid.NewGuid():N}.txt");

    public void Dispose()
    {
        if (File.Exists(_secretFilePath)) File.Delete(_secretFilePath);
    }

    private static IConfiguration BuildConfig(Dictionary<string, string?> values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    [Fact]
    public void DirectEnvVar_IsReturnedAsIs_WhenNoFileVariantIsSet()
    {
        var config = BuildConfig(new() { ["MY_SECRET"] = "direct-value" });
        Assert.Equal("direct-value", SecretConfig.Read(config, "MY_SECRET"));
    }

    [Fact]
    public void FileVariant_TakesPrecedence_AndIsTrimmed()
    {
        File.WriteAllText(_secretFilePath, "  from-the-file  \n");
        var config = BuildConfig(new()
        {
            ["MY_SECRET"] = "direct-value-should-be-ignored",
            ["MY_SECRET_FILE"] = _secretFilePath,
        });

        Assert.Equal("from-the-file", SecretConfig.Read(config, "MY_SECRET"));
    }

    [Fact]
    public void NeitherVariantSet_ReturnsNull()
    {
        var config = BuildConfig([]);
        Assert.Null(SecretConfig.Read(config, "MY_SECRET"));
    }
}
