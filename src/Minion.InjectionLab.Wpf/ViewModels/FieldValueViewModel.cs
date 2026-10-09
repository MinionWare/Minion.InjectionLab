using CommunityToolkit.Mvvm.ComponentModel;
using Minion.InjectionLab.Core.Models;

namespace Minion.InjectionLab.Wpf.ViewModels;

public partial class FieldValueViewModel : ObservableObject
{
    public FormField Field { get; }

    [ObservableProperty]
    private string value;

    public FieldValueViewModel(FormField field)
    {
        Field = field;
        value = field.DefaultValue;
    }
}
