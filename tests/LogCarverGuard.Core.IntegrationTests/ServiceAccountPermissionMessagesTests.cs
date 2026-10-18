using Microsoft.Data.SqlClient;

namespace LogCarverGuard.Core.IntegrationTests;

public class ServiceAccountPermissionMessagesTests
{
    private const string Master = "Server=localhost;Database=master;Integrated Security=true;TrustServerCertificate=true;";
    private const string ServiceLogin = "LogCarverGuard_PermMsg_Service";
    private const string TargetLogin = "LogCarverGuard_PermMsg_Target";
    private const string Password = "PermMsg_Pw_2026_qWe!";

    private static async Task ExecAsync(string sql)
    {
        await using var connection = new SqlConnection(Master);
        await connection.OpenAsync();
        await using var command = new SqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task ServiceAccountWithoutImpersonate_GetsAMessageNamingTheServiceAccountAndThePermission()
    {
        // Real SQL Server answer (error 15406) when the proxy's own login has not been
        // granted IMPERSONATE on the caller's login: it lumps "does not exist", "cannot be
        // impersonated" and "no permission" together and never says whose permission is missing.
        await ExecAsync($@"
            IF SUSER_ID('{ServiceLogin}') IS NULL CREATE LOGIN [{ServiceLogin}] WITH PASSWORD = '{Password}', CHECK_POLICY = OFF;
            IF SUSER_ID('{TargetLogin}') IS NULL CREATE LOGIN [{TargetLogin}] WITH PASSWORD = '{Password}', CHECK_POLICY = OFF;");
        try
        {
            var factory = new ImpersonatedConnectionFactory(
                $"Server=localhost;Database=master;User Id={ServiceLogin};Password={Password};TrustServerCertificate=true;");

            var ex = await Assert.ThrowsAsync<SqlException>(async () =>
            {
                await using var connection = await factory.OpenAsync(TargetLogin);
            });

            string? message = ServiceAccountPermissionMessages.DescribeImpersonationFailure(ex, TargetLogin);

            Assert.NotNull(message);
            Assert.Contains("service account", message);
            Assert.Contains("IMPERSONATE", message);
            Assert.Contains(TargetLogin, message);
        }
        finally
        {
            SqlConnection.ClearAllPools();
            await ExecAsync($@"
                IF SUSER_ID('{ServiceLogin}') IS NOT NULL DROP LOGIN [{ServiceLogin}];
                IF SUSER_ID('{TargetLogin}') IS NOT NULL DROP LOGIN [{TargetLogin}];");
        }
    }
}
