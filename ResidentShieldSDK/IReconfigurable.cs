namespace Malward.ResidentShield;

public interface IReconfigurable
{
    Task<bool> ReconfigureAsync(CancellationToken ct);
}
