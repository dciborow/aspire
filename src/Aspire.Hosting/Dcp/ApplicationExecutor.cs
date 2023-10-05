// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Net.Sockets;
using Aspire.Hosting.ApplicationModel;
using Aspire.Hosting.Dcp.Model;
using k8s;

namespace Aspire.Hosting.Dcp;

internal class AppResource
{
    public IDistributedApplicationComponent Component { get; private set; }
    public CustomResource Resource { get; private set; }
    public virtual List<ServiceAppResource> ServicesProduced { get; private set; } = new();
    public virtual List<ServiceAppResource> ServicesConsumed { get; private set; } = new();

    public AppResource(IDistributedApplicationComponent component, CustomResource resource)
    {
        this.Component = component;
        this.Resource = resource;
    }
}

internal sealed class ServiceAppResource : AppResource
{
    public Service Service => (Service)Resource;
    public ServiceBindingAnnotation ServiceBindingAnnotation { get; private set; }
    public ServiceProducerAnnotation DcpServiceProducerAnnotation { get; private set; }
    public override List<ServiceAppResource> ServicesProduced
    {
        get { throw new InvalidOperationException("Service resources do not produce any services"); }
    }
    public override List<ServiceAppResource> ServicesConsumed
    {
        get { throw new InvalidOperationException("Service resources do not consume any services"); }
    }

    public ServiceAppResource(IDistributedApplicationComponent component, Service service, ServiceBindingAnnotation sba) : base(component, service)
    {
        ServiceBindingAnnotation = sba;
        DcpServiceProducerAnnotation = new(service.Metadata.Name);
    }
}

internal sealed class ApplicationExecutor(DistributedApplicationModel model) : IDisposable
{
    private const string DebugSessionPortVar = "DEBUG_SESSION_PORT";

    private readonly DistributedApplicationModel _model = model;
    private readonly List<AppResource> _appResources = new();
    private readonly KubernetesService _kubernetesService = new();

    public async Task RunApplicationAsync(CancellationToken cancellationToken = default)
    {
        AspireEventSource.Instance.DcpModelCreationStart();
        try
        {
            PrepareServices();
            PrepareContainers();
            PrepareExecutables();

            await CreateServicesAsync(cancellationToken).ConfigureAwait(false);

            await CreateContainersAndExecutablesAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            AspireEventSource.Instance.DcpModelCreationStop();
        }

    }

    public async Task StopApplicationAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            AspireEventSource.Instance.DcpModelCleanupStart();
            await DeleteResourcesAsync<ExecutableReplicaSet>("project", cancellationToken).ConfigureAwait(false);
            await DeleteResourcesAsync<Executable>("project", cancellationToken).ConfigureAwait(false);
            await DeleteResourcesAsync<Container>("container", cancellationToken).ConfigureAwait(false);
            await DeleteResourcesAsync<Service>("service", cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            AspireEventSource.Instance.DcpModelCleanupStop();
            _appResources.Clear();
        }
    }

    private async Task CreateServicesAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            AspireEventSource.Instance.DcpServicesCreationStart();

            var needAddressAllocated = _appResources.OfType<ServiceAppResource>().Where(sr => !sr.Service.HasCompleteAddress).ToList();
            if (needAddressAllocated.Count == 0)
            {
                // No need to wait for any updates to Service objects from the orchestrator.
                await CreateResourcesAsync<Service>(cancellationToken).ConfigureAwait(false);
                return;
            }

            // Start the watcher before creating new Services so that we do not miss any updates.
            IAsyncEnumerable<(WatchEventType, Service)> serviceChangeEnumerator = _kubernetesService.WatchAsync<Service>(cancellationToken: cancellationToken);

            await CreateResourcesAsync<Service>(cancellationToken).ConfigureAwait(false);

            await foreach (var (evt, updated) in serviceChangeEnumerator)
            {
                if (evt == WatchEventType.Bookmark) { continue; } // Bookmarks do not contain any data.

                var srvResource = needAddressAllocated.Where(sr => sr.Service.Metadata.Name == updated.Metadata.Name).FirstOrDefault();
                if (srvResource == null) { continue; } // This service most likely already has full address information, so it is not on needAddressAllocated list.

                if (updated.HasCompleteAddress)
                {
                    srvResource.Service.ApplyAddressInfoFrom(updated);
                    needAddressAllocated.Remove(srvResource);
                }

                if (needAddressAllocated.Count == 0)
                {
                    return; // We are done
                }
            }
        }
        finally
        {
            AspireEventSource.Instance.DcpServicesCreationStop();
        }
    }

    private async Task CreateContainersAndExecutablesAsync(CancellationToken cancellationToken)
    {
        var toCreate = _appResources.Where(r => r.Resource is Container || r.Resource is Executable || r.Resource is ExecutableReplicaSet);
        AddAllocatedEndpointInfo(toCreate);

        await CreateContainersAsync(toCreate.Where(ar => ar.Resource is Container), cancellationToken).ConfigureAwait(false);
        await CreateExecutablesAsync(toCreate.Where(ar => ar.Resource is Executable || ar.Resource is ExecutableReplicaSet), cancellationToken).ConfigureAwait(false);
    }

    private static void AddAllocatedEndpointInfo(IEnumerable<AppResource> resources)
    {
        foreach (var appResource in resources)
        {
            foreach (var sp in appResource.ServicesProduced)
            {
                var svc = (Service)sp.Resource;
                if (!svc.HasCompleteAddress)
                {
                    // This should never happen; if it does, we have a bug without a workaround for th the user.
                    throw new InvalidDataException($"Service {svc.Metadata.Name} should have valid address at this point");
                }

                var a = new AllocatedEndpointAnnotation(
                    sp.ServiceBindingAnnotation.Name,
                    PortProtocol.ToProtocolType(svc.Spec.Protocol),
                    svc.AllocatedAddress!,
                    (int)svc.AllocatedPort!,
                    sp.ServiceBindingAnnotation.UriScheme
                    );

                appResource.Component.Annotations.Add(a);
            }
        }
    }

    private void PrepareServices()
    {
        var serviceProducers = _model.Components
            .Select(c => (Component: c, SBAnnotations: c.Annotations.OfType<ServiceBindingAnnotation>()))
            .Where(sp => sp.SBAnnotations.Any());

        // We need to ensure that Services have unique names (otherwise we cannot really distinguish between
        // services produced by different components).
        List<string> serviceNames = new();

        void addServiceAppResource(Service svc, IDistributedApplicationComponent producingComponent, ServiceBindingAnnotation sba)
        {
            svc.Spec.Protocol = PortProtocol.FromProtocolType(sba.Protocol);
            svc.Spec.AddressAllocationMode = AddressAllocationModes.IPv4Loopback;

            _appResources.Add(new ServiceAppResource(producingComponent, svc, sba));
        }

        foreach (var sp in serviceProducers)
        {
            var sbAnnotations = sp.SBAnnotations.ToArray();
            var replicas = sp.Component.GetReplicaCount();

            foreach (var sba in sbAnnotations)
            {
                var candidateServiceName = sbAnnotations.Length == 1 ?
                    GetObjectNameForComponent(sp.Component) : GetObjectNameForComponent(sp.Component, sba.Name);
                var uniqueServiceName = GenerateUniqueServiceName(serviceNames, candidateServiceName);
                var svc = Service.Create(uniqueServiceName);

                if (replicas > 1)
                {
                    // Treat the port specified in the ServiceBindingAnnotation as desired port for the whole service.
                    // Each replica receives its own port.
                    svc.Spec.Port = sba.Port;
                }

                addServiceAppResource(svc, sp.Component, sba);
            }
        }
    }

    private void PrepareExecutables()
    {
        PrepareProjectExecutables();
        PreparePlainExecutables();
    }

    private void PreparePlainExecutables()
    {
        var executableComponents = _model.GetExecutableComponents();

        foreach (var executable in executableComponents)
        {
            var exeName = GetObjectNameForComponent(executable);
            var exePath = Path.GetFullPath(executable.Command);
            var exe = Executable.Create(exeName, exePath);

            exe.Spec.WorkingDirectory = executable.WorkingDirectory;
            exe.Spec.Args = executable.Args?.ToList();
            exe.Spec.ExecutionType = ExecutionType.Process;

            var exeAppResource = new AppResource(executable, exe);
            AddServicesProducedInfo(executable, exe, exeAppResource);
            _appResources.Add(exeAppResource);
        }
    }

    private void PrepareProjectExecutables()
    {
        var projectComponents = _model.GetProjectComponents();

        foreach (var project in projectComponents)
        {
            if (!project.TryGetLastAnnotation<IServiceMetadata>(out var projectMetadata))
            {
                throw new InvalidOperationException("A project component is missing required metadata"); // Should never happen.
            }

            CustomResource workload;
            ExecutableSpec exeSpec;
            IAnnotationHolder annotationHolder;
            var workloadName = GetObjectNameForComponent(project);
            int replicas = project.GetReplicaCount();

            if (replicas > 1)
            {
                var ers = ExecutableReplicaSet.Create(workloadName, replicas, "dotnet");
                exeSpec = ers.Spec.Template.Spec;
                annotationHolder = ers.Spec.Template;
                workload = ers;
            }
            else
            {
                var exe = Executable.Create(workloadName, "dotnet");
                exeSpec = exe.Spec;
                annotationHolder = workload = exe;
            }

            exeSpec.WorkingDirectory = Path.GetDirectoryName(projectMetadata.ProjectPath);

            annotationHolder.Annotate(Executable.CSharpProjectPathAnnotation, projectMetadata.ProjectPath);
            annotationHolder.Annotate(Executable.LaunchProfileNameAnnotation, project.SelectLaunchProfileName() ?? string.Empty);

            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(DebugSessionPortVar)))
            {
                exeSpec.ExecutionType = ExecutionType.IDE;
            }
            else
            {
                exeSpec.ExecutionType = ExecutionType.Process;
                if (Environment.GetEnvironmentVariable("DOTNET_WATCH") != "1")
                {
                    exeSpec.Args = new List<string> {
                        "run",
                        "--no-build",
                        "--project", projectMetadata.ProjectPath,
                    };
                }
                else
                {
                    exeSpec.Args = new List<string> {
                        "watch",
                        "--project", projectMetadata.ProjectPath
                    };
                }

                // We pretty much always want to suppress the normal launch profile handling
                // because the settings from the profile will override the ambient environment settings, which is not what we want
                // (the ambient environment settings for service processes come from the application model
                // and should be HIGHER priority than the launch profile settings).
                // This means we need to apply the launch profile settings manually--the invocation parameters here,
                // and the environment variables/application URLs inside CreateExecutableAsync().
                exeSpec.Args.Add("--no-launch-profile");

                string? launchProfileName = project.SelectLaunchProfileName();
                if (!string.IsNullOrEmpty(launchProfileName))
                {
                    var launchProfile = project.GetEffectiveLaunchProfile();
                    if (launchProfile is not null && !string.IsNullOrWhiteSpace(launchProfile.CommandLineArgs))
                    {
                        var cmdArgs = launchProfile.CommandLineArgs.Split((string?)null, StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                        if (cmdArgs is not null && cmdArgs.Length > 0)
                        {
                            exeSpec.Args.Add("--");
                            exeSpec.Args.AddRange(cmdArgs);
                        }
                    }
                }
            }

            var exeAppResource = new AppResource(project, workload);
            AddServicesProducedInfo(project, annotationHolder, exeAppResource);
            _appResources.Add(exeAppResource);
        }
    }

    private async Task CreateExecutablesAsync(IEnumerable<AppResource> executableResources, CancellationToken cancellationToken)
    {
        try
        {
            AspireEventSource.Instance.DcpExecutablesCreateStart();

            foreach (var er in executableResources)
            {
                ExecutableSpec spec;
                Func<Task<CustomResource>> createResource;

                switch (er.Resource)
                {
                    case Executable exe:
                        spec = exe.Spec;
                        createResource = async () => await _kubernetesService.CreateAsync(exe, cancellationToken).ConfigureAwait(false);
                        break;
                    case ExecutableReplicaSet ers:
                        spec = ers.Spec.Template.Spec;
                        createResource = async () => await _kubernetesService.CreateAsync(ers, cancellationToken).ConfigureAwait(false);
                        break;
                    default:
                        throw new InvalidOperationException($"Expected an Executable-like resource, but got {er.Resource.Kind} instead");
                }

                spec.Args ??= new();

                if (er.Component.TryGetAnnotationsOfType<ExecutableArgsCallbackAnnotation>(out var exeArgsCallbacks))
                {
                    foreach (var exeArgsCallback in exeArgsCallbacks)
                    {
                        exeArgsCallback.Callback(spec.Args);
                    }
                }

                var config = new Dictionary<string, string>();
                var context = new EnvironmentCallbackContext("dcp", config);

                // Need to apply configuration settings manually; see PrepareExecutables() for details.
                if (er.Component is ProjectComponent project && project.SelectLaunchProfileName() is { } launchProfileName && project.GetLaunchSettings() is { } launchSettings)
                {
                    ApplyLaunchProfile(er, config, launchProfileName, launchSettings);
                }

                if (er.Component.TryGetEnvironmentVariables(out var envVarAnnotations))
                {
                    foreach (var ann in envVarAnnotations)
                    {
                        ann.Callback(context);
                    }
                }

                spec.Env = new();
                foreach (var c in config)
                {
                    spec.Env.Add(new EnvVar { Name = c.Key, Value = c.Value });
                }

                var createdExecutable = await createResource().ConfigureAwait(false);
                var dcpResourceAnnotation = new DcpResourceAnnotation(createdExecutable.Metadata.NamespaceProperty, createdExecutable.Metadata.Name, createdExecutable.Kind);
                er.Component.Annotations.Add(dcpResourceAnnotation);
            }

        }
        finally
        {
            AspireEventSource.Instance.DcpExecutablesCreateStop();
        }
    }

    private static void ApplyLaunchProfile(AppResource executableResource, Dictionary<string, string> config, string launchProfileName, LaunchSettings launchSettings)
    {
        // Populate DOTNET_LAUNCH_PROFILE environment variable for consistency with "dotnet run" and "dotnet watch".
        config.Add("DOTNET_LAUNCH_PROFILE", launchProfileName);

        var launchProfile = launchSettings.Profiles[launchProfileName];
        if (!string.IsNullOrWhiteSpace(launchProfile.ApplicationUrl))
        {
            int replicas = executableResource.Component.GetReplicaCount();

            if (replicas > 1)
            {
                // Can't use the information in ASPNETCORE_URLS directly when multiple replicas are in play.
                // Instead we are going to SYNTHESIZE the new ASPNETCORE_URLS value based on the information about services produced by this component.
                var urls = executableResource.ServicesProduced.Select(sar =>
                {
                    var url = sar.ServiceBindingAnnotation.UriScheme + "://localhost:{{- portForServing \"" + sar.Service.Metadata.Name + "\" -}}";
                    return url;
                });
                config.Add("ASPNETCORE_URLS", string.Join(";", urls));
            }
            else
            {
                config.Add("ASPNETCORE_URLS", launchProfile.ApplicationUrl);
            }
        }

        foreach (var envVar in launchProfile.EnvironmentVariables)
        {
            string value = Environment.ExpandEnvironmentVariables(envVar.Value);
            config[envVar.Key] = value;
        }
    }

    private void PrepareContainers()
    {
        var containerComponents = _model.GetContainerComponents();

        foreach (var container in containerComponents)
        {
            if (!container.TryGetContainerImageName(out var containerImageName))
            {
                // This should never happen! In order to get into this loop we need
                // to have the annotation, if we don't have the annotation by the time
                // we get here someone is doing something wrong.
                throw new InvalidOperationException();
            }

            var computedContainerName = container.TryGetName(out var specifiedContainerName) ? specifiedContainerName : containerImageName;
            // TODO: the image name is really not the best name for Container object; we should use a "service name" or "component name"
            var ctr = Container.Create(computedContainerName, containerImageName);

            if (container.TryGetVolumeMounts(out var volumeMounts))
            {
                ctr.Spec.VolumeMounts = new();

                foreach (var mount in volumeMounts)
                {
                    bool isBound = mount.Type == ApplicationModel.VolumeMountType.Bind;
                    var volumeSpec = new VolumeMount()
                    {
                        Source = isBound ? Path.GetFullPath(mount.Source) : mount.Source,
                        Target = mount.Target,
                        Type = isBound ? Model.VolumeMountType.Bind : Model.VolumeMountType.Named,
                        IsReadOnly = mount.IsReadOnly
                    };
                    ctr.Spec.VolumeMounts.Add(volumeSpec);
                }
            }

            var containerAppResource = new AppResource(container, ctr);
            AddServicesProducedInfo(container, ctr, containerAppResource);
            _appResources.Add(containerAppResource);
        }
    }

    private async Task CreateContainersAsync(IEnumerable<AppResource> containerResources, CancellationToken cancellationToken)
    {
        try
        {
            AspireEventSource.Instance.DcpContainersCreateStart();

            foreach (var cr in containerResources)
            {
                var container = (Container)cr.Resource;
                var containerComponent = cr.Component;

                container.Spec.Env = new();

                if (containerComponent.TryGetEnvironmentVariables(out var containerEnvironmentVariables))
                {
                    var config = new Dictionary<string, string>();
                    var context = new EnvironmentCallbackContext("dcp", config);

                    foreach (var v in containerEnvironmentVariables)
                    {
                        v.Callback(context);
                    }

                    foreach (var kvp in config)
                    {
                        container.Spec.Env.Add(new EnvVar { Name = kvp.Key, Value = kvp.Value });
                    }
                }

                if (cr.ServicesProduced.Count > 0)
                {
                    container.Spec.Ports = new();

                    foreach (var sp in cr.ServicesProduced)
                    {
                        var portSpec = new ContainerPortSpec()
                        {
                            ContainerPort = sp.DcpServiceProducerAnnotation.Port,
                        };

                        if (!string.IsNullOrEmpty(sp.DcpServiceProducerAnnotation.Address))
                        {
                            portSpec.HostIP = sp.DcpServiceProducerAnnotation.Address;
                        }

                        if (sp.ServiceBindingAnnotation.Port is not null)
                        {
                            portSpec.HostPort = sp.ServiceBindingAnnotation.Port;
                        }

                        switch (sp.ServiceBindingAnnotation.Protocol)
                        {
                            case ProtocolType.Tcp:
                                portSpec.Protocol = PortProtocol.TCP; break;
                            case ProtocolType.Udp:
                                portSpec.Protocol = PortProtocol.UDP; break;
                        }

                        container.Spec.Ports.Add(portSpec);
                    }
                }

                var createdContainer = await _kubernetesService.CreateAsync(container, cancellationToken).ConfigureAwait(false);
                var dcpResourceAnnotation = new DcpResourceAnnotation(createdContainer.Metadata.NamespaceProperty, createdContainer.Metadata.Name, createdContainer.Kind);
                cr.Component.Annotations.Add(dcpResourceAnnotation);
            }
        }
        finally
        {
            AspireEventSource.Instance.DcpContainersCreateStop();
        }
    }

    private void AddServicesProducedInfo(IDistributedApplicationComponent component, IAnnotationHolder dcpResource, AppResource appResource)
    {
        string componentName = "(unknown)";
        try
        {
            componentName = GetObjectNameForComponent(component);
        }
        catch { } // For error messages only, OK to fall back to (unknown)

        var servicesProduced = _appResources.OfType<ServiceAppResource>().Where(r => r.Component == component);
        foreach (var sp in servicesProduced)
        {
            if (component.IsContainer())
            {
                if (sp.ServiceBindingAnnotation.ContainerPort is null)
                {
                    throw new InvalidOperationException($"The ServiceBindingAnnotation for container component {componentName} must specify the ContainerPort");
                }

                sp.DcpServiceProducerAnnotation.Port = sp.ServiceBindingAnnotation.ContainerPort;
            }
            else if (component is ExecutableComponent)
            {
                sp.DcpServiceProducerAnnotation.Port = sp.ServiceBindingAnnotation.Port;
            }
            else
            {
                if (sp.ServiceBindingAnnotation.Port is null)
                {
                    throw new InvalidOperationException($"The ServiceBindingAnnotation for component {componentName} must specify the Port");
                }

                if (component.GetReplicaCount() == 1)
                {
                    // If multiple replicas are used, each replica will get its own port.
                    sp.DcpServiceProducerAnnotation.Port = sp.ServiceBindingAnnotation.Port;
                }
            }

            dcpResource.AnnotateAsObjectList(CustomResource.ServiceProducerAnnotation, sp.DcpServiceProducerAnnotation);
            appResource.ServicesProduced.Add(sp);
        }
    }

    private async Task CreateResourcesAsync<RT>(CancellationToken cancellationToken) where RT : CustomResource
    {
        var resourcesToCreate = _appResources.Select(r => r.Resource).OfType<RT>();
        if (!resourcesToCreate.Any())
        {
            return;
        }

        // CONSIDER batched creation
        foreach (var res in resourcesToCreate)
        {
            await _kubernetesService.CreateAsync(res, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task DeleteResourcesAsync<RT>(string resourceName, CancellationToken cancellationToken) where RT : CustomResource
    {
        var resourcesToDelete = _appResources.Select(r => r.Resource).OfType<RT>();
        if (!resourcesToDelete.Any())
        {
            return;
        }

        foreach (var res in resourcesToDelete)
        {
            try
            {
                await _kubernetesService.DeleteAsync<RT>(res.Metadata.Name, res.Metadata.NamespaceProperty, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Could not stop {resourceName} '{res.Metadata.Name}': {ex}");
            }
        }
    }

    public void Dispose()
    {
        _kubernetesService.Dispose();
    }

    private static string GetObjectNameForComponent(IDistributedApplicationComponent component, string suffix = "")
    {
        string maybeWithSuffix(string s) => string.IsNullOrWhiteSpace(suffix) ? s : $"{s}_{suffix}";

        if (component.TryGetName(out var name))
        {
            return maybeWithSuffix(name);
        }

        switch (component)
        {
            case ContainerComponent:
                if (!component.TryGetContainerImageName(out var imageName))
                {
                    throw new ArgumentException("The container component has no name and no image information."); // Should never happen.
                }

                if (Rules.IsValidObjectName(imageName))
                {
                    return maybeWithSuffix(imageName);
                }
                else
                {
                    throw new ArgumentException($"Could not determine a good name for container component using image '{imageName}'; use WithName() on the container to fix this issue.");
                }

            case ProjectComponent:
                if (!component.TryGetLastAnnotation<IServiceMetadata>(out var projectMetadata))
                {
                    throw new ArgumentException("The project component has no name and no project metadata"); // Should never happen.
                }

                // TODO: the assembly name is really not the best name for Executable object (should use project name probably).
                if (Rules.IsValidObjectName(projectMetadata.AssemblyName))
                {
                    return maybeWithSuffix(projectMetadata.AssemblyName);
                }
                else
                {
                    throw new ArgumentException($"Could not determine a good name for project component with assembly name '{projectMetadata.AssemblyName}'; use WithName() on the project to fix this issue.");
                }

            default:
                throw new ArgumentException($"Could not determine a good name for component of type {component.GetType().Name}");
        }
    }

    private static string GenerateUniqueServiceName(List<string> serviceNames, string candidateName)
    {
        int suffix = 1;
        string uniqueName = candidateName;

        while (serviceNames.Contains(uniqueName))
        {
            uniqueName = $"{candidateName}_{suffix}";
            suffix++;
            if (suffix == 100)
            {
                // Should never happen, but we do not want to ever get into a infinite loop situation either.
                throw new ArgumentException($"Could not generate a unique name for service '{candidateName}'");
            }
        }

        serviceNames.Add(uniqueName);
        return uniqueName;
    }

}
