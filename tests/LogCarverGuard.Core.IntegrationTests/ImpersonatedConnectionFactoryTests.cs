using Microsoft.Data.SqlClient;

namespace LogCarverGuard.Core.IntegrationTests;

[Collection("GuardSqlServer")]
public class ImpersonatedConnectionFactoryTests(GuardedSqlExecutorFixture fixture)
{
    private ImpersonatedConnectionFactory CreateFactory() => new(fixture.ServiceAccountConnectionString);

    [Fact]
    public async Task OpenAsync_SwitchesTheSessionToTheGivenLogin()
    {
        var factory = CreateFactory();
        await using var conn = await factory.OpenAsync(GuardedSqlExecutorFixture.RestrictedLoginName);

        await using var cmd = new SqlCommand("SELECT SUSER_NAME();", conn);
        string? currentLogin = (string?)await cmd.ExecuteScalarAsync();

        Assert.Equal(GuardedSqlExecutorFixture.RestrictedLoginName, currentLogin);
    }

    [Fact]
    public async Task ImpersonatedLogin_CanUseItsGrantedPermission()
    {
        var factory = CreateFactory();
        await using var conn = await factory.OpenAsync(GuardedSqlExecutorFixture.RestrictedLoginName);

        // The fixture grants this login SELECT+UPDATE on GuardTest specifically.
        await using var cmd = new SqlCommand(
            $"UPDATE {GuardedSqlExecutorFixture.TableName} SET Name = 'via-impersonation' WHERE Id = 1;", conn);
        int rowsAffected = await cmd.ExecuteNonQueryAsync();

        Assert.Equal(1, rowsAffected);
    }

    [Fact]
    public async Task ImpersonatedLogin_IsDeniedOnATableItWasNeverGrantedPermissionOn()
    {
        // This is the real point of EXECUTE AS LOGIN here: permission
        // checks must follow the impersonated login, not the service
        // account that physically opened the connection (which is
        // sysadmin in this dev sandbox and would otherwise bypass every
        // check). If this ever starts passing without the fix, something
        // broke the impersonation, not the grant.
        var factory = CreateFactory();
        await using var conn = await factory.OpenAsync(GuardedSqlExecutorFixture.RestrictedLoginName);

        await using var cmd = new SqlCommand(
            $"DELETE FROM {GuardedSqlExecutorFixture.ParentTableName} WHERE Id = 1;", conn);

        var ex = await Assert.ThrowsAsync<SqlException>(() => cmd.ExecuteNonQueryAsync());
        // 229 = permission denied on object - checked by number, not message
        // text, since SQL Server's error message is locale-dependent (this
        // dev box is zh-TW).
        Assert.Equal(229, ex.Number);
    }

    [Fact]
    public async Task OpenAsync_DisablesConnectionPooling()
    {
        var factory = CreateFactory();
        await using var conn = await factory.OpenAsync(GuardedSqlExecutorFixture.RestrictedLoginName);

        var builder = new SqlConnectionStringBuilder(conn.ConnectionString);
        Assert.False(builder.Pooling);
    }
}
