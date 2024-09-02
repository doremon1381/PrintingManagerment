namespace PrintingManagermentServer.Client
{
    public record ClientSettings(
            string client_id,
            string auth_uri,
            string userinfo_uri,
            string updateUser_uri,
            string forgotPassword_uri,
            string google_auth_uri,
            string register_uri,
            string token_uri,
            string client_secret,
            string[] redirect_uris
        );

}
