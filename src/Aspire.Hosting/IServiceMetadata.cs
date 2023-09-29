// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Aspire.Hosting.ApplicationModel;

namespace Aspire.Hosting;

public interface IServiceMetadata : IDistributedApplicationComponentAnnotation
{
    public string AssemblyName { get; }
    public string AssemblyPath { get; }
    public string ProjectPath { get; }
}