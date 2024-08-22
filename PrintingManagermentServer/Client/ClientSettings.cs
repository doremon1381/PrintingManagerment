namespace PrintingManagermentServer.Client
{
    public record ClientSettings(
            string client_id,
            string auth_uri,
            string register_uri,
            string token_uri,
            string client_secret,
            string[] redirect_uris
        );

}
