namespace Minion.InjectionLab.Core.Models;

public enum Severity
{
    Blocked,    // fix applied, attack neutralized
    Info,       // nothing notable happened
    Warning,    // partial leak / behavior change
    Critical    // full bypass, data exfiltration, or equivalent
}
