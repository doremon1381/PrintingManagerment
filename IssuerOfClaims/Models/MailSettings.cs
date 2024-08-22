namespace IssuerOfClaims.Models
{
    public class MailSettings
    {
        public string EmailId { get; set; }
        public string Name { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Host { get; set; }
        public int Port { get; set; }
        public bool UseSSL { get; set; }
        public bool DefaultCredentials {  get; set; }
    }

    public static class MailKitConfig
    {
        public const string EMAIL_ID = "EmailId";
        public const string NAME = "Name";
        public const string USER_NAME = "UserName";
        public const string PASSWORD = "UserName";
        public const string HOST = "UserName";
        public const string PORT = "UserName";
        public const string USESSL = "UserName";
        public const string DEFAULT_CREDENTIALS = "UserName";
    }
}
