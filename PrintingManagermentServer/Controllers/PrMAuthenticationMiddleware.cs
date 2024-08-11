using Microsoft.AspNetCore.Http;
using PrMServerUltilities.Identity;
using System.Net;

namespace PrintingManagermentServer.Controllers
{
    /// <summary>
    /// from https://dotnettutorials.net/lesson/401-http-status-codein-asp-net-core-web-api/#:~:text=The%20HTTP%20401%20Status%20Code,to%20get%20the%20requested%20response.
    /// </summary>
    public class PrMAuthenticationMiddleware
    {
        // Field to store the next middleware in the pipeline
        private readonly RequestDelegate _next;
        private readonly IConfigurationManager _configuration;

        // Constructor to initialize the middleware with the next RequestDelegate
        public PrMAuthenticationMiddleware(RequestDelegate next, IConfigurationManager configuration)
        {
            _next = next; // Assign the next middleware to the private field
            _configuration = configuration;
        }

        // Method that gets called for each request to handle authentication
        public async Task InvokeAsync(HttpContext context)
        {
            // Custom authorization logic here
            bool isAuthorized = CheckAuthorization(context); // Call the method to check authorization

            if (!isAuthorized) // If the user is not authorized
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized; // Set the response status code to 401
                context.Response.ContentType = "application/json"; // Set the response content type to JSON

                var identityServerInfo = _configuration.GetSection(IdentityServerConfiguration.IDENTITYSERVER);

                var identityServerUri = identityServerInfo[IdentityServerConfiguration.AUTHORIZATION_ENDPOINT];
                var clientId = identityServerInfo["client_id"];
                var redirectUri = identityServerInfo["redirect_uris:0"];

                var responseRedirectUri = string.Format("{0}?client_id={1}" +
                    "&redirect_uri={2}", identityServerUri, clientId, redirectUri);
                // TODO: will try to implement nonce
                //+ "&nonce={}");

                // Create a custom response object
                var customResponse = new
                {
                    status = 401, // Status code
                    message = "Unauthorized. Please Provide Valid Credentials" // Custom message
                };

                context.Response.Headers.Add("Location", responseRedirectUri);
                //context.Response.Redirect(redirectUri);

                //context.Response.OnCompleted();
                // Serialize the custom response object to JSON and write it to the response body
                //await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(customResponse));
                //await _next(context);
                //return Unauthorized();
                return;// Short-circuit the pipeline, preventing further middleware execution
            }

            // If the user is authorized, pass the request to the next middleware in the pipeline
            await _next(context);
        }

        // Private method to check authorization
        private bool CheckAuthorization(HttpContext context)
        {
            // Implement your authorization logic here
            // For example, check for a specific header or token

            var isAuthorized = context.User == null ? false : context.User.Identity.IsAuthenticated;

            // Simulate unauthorized for this example
            return isAuthorized; // Always return false to simulate an unauthorized request
        }
    }
}
