namespace Minion.InjectionLab.Core.Models;

public enum Severity
{
    Success,    // a legitimate operation worked exactly as intended — not an attack outcome
    Blocked,    // fix applied, attack neutralized
    Info,       // nothing notable happened (e.g. an ordinary failed login)
    Warning,    // partial leak / behavior change
    Critical    // full bypass, data exfiltration, or equivalent
}
