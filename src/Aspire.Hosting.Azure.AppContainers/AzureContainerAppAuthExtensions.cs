using Aspire.Hosting.ApplicationModel;
using Azure.Provisioning.AppContainers;

namespace Aspire.Hosting;

/// <summary>
/// Extension methods for enabling Azure authentication on container apps.
/// </summary>
public static class AzureContainerAppAuthExtensions
{
    /// <summary>
    /// Enables Azure Authentication (Easy Auth) for a container app.
    /// </summary>
    /// <typeparam name="T">The project type.</typeparam>
    /// <param name="project">The project resource builder.</param>
    /// <param name="clientId">The AAD client id or <c>env:VAR</c> expression.</param>
    /// <param name="tenantId">The tenant id or <c>env:VAR</c> expression.</param>
    /// <param name="clientSecretEnv">Optional secret environment variable name.</param>
    /// <returns>The updated project resource builder.</returns>
    public static IResourceBuilder<T> WithAzureAuthentication<T>(this IResourceBuilder<T> project, string clientId, string tenantId, string? clientSecretEnv = "AAD_CLIENT_SECRET") where T : ProjectResource
    {
        ArgumentNullException.ThrowIfNull(project);
        ArgumentException.ThrowIfNullOrEmpty(clientId);
        ArgumentException.ThrowIfNullOrEmpty(tenantId);

        project.WithEnvironment("AZURE_CLIENT_ID", clientId);
        project.WithEnvironment("AZURE_TENANT_ID", tenantId);

        if (!string.IsNullOrEmpty(clientSecretEnv))
        {
            project.WithEnvironment(clientSecretEnv, $"env:{clientSecretEnv}");
        }

        if (project.ApplicationBuilder.ExecutionContext.IsPublishMode)
        {
            project.PublishAsAzureContainerApp((infra, app) =>
            {
                var issuer = tenantId.StartsWith("env:", StringComparison.OrdinalIgnoreCase)
                    ? ReferenceExpression.Create($"https://login.microsoftonline.com/{{{tenantId.Substring(4)}}}/v2.0")
                    : $"https://login.microsoftonline.com/{tenantId}/v2.0";

                app.Configuration.Auth = new ContainerAppAuth()
                {
                    Platform = new ContainerAppAuthPlatform() { Enabled = true },
                    UnauthenticatedClientAction = ContainerAppUnauthenticatedClientAction.RedirectToLoginPage,
                    IdentityProviders = new ContainerAppIdentityProviders()
                    {
                        AzureActiveDirectory = new ContainerAppAzureActiveDirectory()
                        {
                            Enabled = true,
                            Registration = new ContainerAppAzureActiveDirectoryRegistration()
                            {
                                ClientId = clientId,
                                ClientSecretSettingName = clientSecretEnv,
                                OpenIdIssuer = issuer
                            }
                        }
                    }
                };
            });
        }

        return project;
    }
}
