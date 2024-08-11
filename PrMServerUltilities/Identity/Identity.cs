namespace PrMServerUltilities.Identity
{
    public static class ResponseType
    {
        public static string IdToken = "id_token";
    }

    public static class ResponseMode
    {
        public static string FormPost = "form_post";
    }

    public static class IdentityServerConfiguration
    {
        public const string SCHEME_BASIC = "Basic";
        public const string GOOGLE_CLIENT = "GoogleClient";
        public const string WEB_SERVER = "WebServer";
        public const string PROJECT_ID = "project_id";
        public const string IDENTITYSERVER = "IdentityServer";
        public const string CLIENT_ID = "client_id";
        public const string CLIENT_SECRET = "client_secret";
        public const string REDIRECT_URIS = "redirect_uris";
        public const string AUTHORIZATION_ENDPOINT = "auth_uri";
        public const string REGISTER_ENDPOINT = "register_uri";
        public const string TOKEN_ENDPOINT = "token_uri";
    }
}
