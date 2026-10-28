namespace Settings;

public static class Defaults
{
    // Base64 of a short settings file.
    public const string Encoded =
        "ZW5kcG9pbnQ9aHR0cHM6Ly9leGFtcGxlLmNvbS9hcGkvaXRlbXMKcmV0cnk9MwplbmRwb2ludD1odHRwczovL2V4YW1wbGUuY29tL2FwaS9pdGVtcwpyZXRyeT0zCmVuZHBvaW50PWh0dHBzOi8vZXhhbXBsZS5jb20vYXBpL2l0ZW1zCnJldHJ5PTMKZW5kcG9pbnQ9aHR0cHM6Ly9leGFtcGxlLmNvbS9hcGkvaXRlbXMKcmV0cnk9Mwo=";

    public static string Text() => System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(Encoded));
}
