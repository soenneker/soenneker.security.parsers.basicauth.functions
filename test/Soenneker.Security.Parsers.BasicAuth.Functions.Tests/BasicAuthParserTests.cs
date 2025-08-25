using Soenneker.Tests.FixturedUnit;
using Xunit;

namespace Soenneker.Security.Parsers.BasicAuth.Functions.Tests;

[Collection("Collection")]
public sealed class BasicAuthParserTests : FixturedUnitTest
{
    public BasicAuthParserTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
    }

    [Fact]
    public void Default()
    {

    }
}
