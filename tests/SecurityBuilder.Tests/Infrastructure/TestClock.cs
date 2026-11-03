namespace SecurityBuilder.Tests.Infrastructure;

/// <summary>A clock the test moves itself, so expiry does not need waiting for.</summary>
internal sealed class TestClock(DateTimeOffset now) : TimeProvider
{
    /// <summary>Starts at the real time, because a signed token's own lifetime is validated against it.</summary>
    public TestClock() : this(DateTimeOffset.UtcNow) { }

    public DateTimeOffset Now { get; private set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;

    public void Advance(TimeSpan by) => Now += by;
}
