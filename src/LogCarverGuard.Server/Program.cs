using LogCarverGuard.Server;

// The free composition: proxy pass-through, statement guard, audit log,
// API keys and IP filtering. No extension is registered, so this process
// needs no privileged connection.
var builder = WebApplication.CreateBuilder(args);
builder.AddLogCarverGuard();

var app = builder.Build();
app.UseLogCarverGuard();
app.Run();

public partial class Program;
