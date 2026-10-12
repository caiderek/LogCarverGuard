using System.Reflection;

namespace LogCarverGuard.Server.Tests;

/// <summary>
/// This host is made of exactly three of this repo's assemblies. A structural
/// check, because "nobody registered the extra code" is a runtime property
/// that a later edit could quietly change, whereas an assembly reference
/// cannot appear by accident.
/// </summary>
public class FreeEditionDependencyTests
{
    [Fact]
    public void Server_ReachesOnlyItsOwnThreeAssemblies()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<AssemblyName>();
        queue.Enqueue(typeof(Program).Assembly.GetName());

        while (queue.Count > 0)
        {
            var name = queue.Dequeue();
            if (!seen.Add(name.Name!))
                continue;

            // Framework and third-party packages cannot reference this repo's
            // code, so there is no need to walk into them.
            if (name.Name!.StartsWith("System", StringComparison.Ordinal)
                || name.Name.StartsWith("Microsoft", StringComparison.Ordinal)
                || name.Name is "netstandard" or "mscorlib" or "WindowsBase")
                continue;

            Assembly assembly;
            try { assembly = Assembly.Load(name); }
            catch (Exception) { continue; }

            foreach (var reference in assembly.GetReferencedAssemblies())
                queue.Enqueue(reference);
        }

        Assert.Contains("LogCarverGuard.Core", seen);       // the walk really reached the code
        Assert.Contains("LogCarverGuard.Hosting", seen);

        string[] allowed = ["LogCarverGuard.Server", "LogCarverGuard.Hosting", "LogCarverGuard.Core"];
        var unexpected = seen.Where(n => n.StartsWith("LogCarver", StringComparison.OrdinalIgnoreCase)
                                         && !allowed.Contains(n, StringComparer.OrdinalIgnoreCase)).ToList();
        Assert.Empty(unexpected);
    }
}
