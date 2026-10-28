// A type named as the marker a transformation tool adds; the code is otherwise unchanged.
internal sealed class ConfusedByAttribute : System.Attribute
{
}

namespace Marker
{
    public static class Program
    {
        public static string Endpoint => "https://example.com/api/items";
    }
}
