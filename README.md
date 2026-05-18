# AccessPolicy Prototype

This repository contains a proof-of-concept implementation of the `AccessPolicy` CRD for the [Kuadrant mcp-gateway](https://github.com/Kuadrant/mcp-gateway) project. 

It was built to validate the approach outlined in the LFX Mentorship proposal regarding tool-level authorization for AI agents.

## Overview

The prototype demonstrates how to implement fine-grained, tool-level access control without building a custom authorization engine from scratch. It leverages the existing Kuadrant Authorino architecture by translating high-level agent access rules into native Kuadrant `AuthPolicy` configurations.

### Key Components

1. **AccessPolicy Controller**: A standard Kubernetes controller that watches for `AccessPolicy` resources and generates the corresponding `AuthPolicy` resources. It relies on the `x-mcp-toolname` header injected by the gateway's `ext-proc` router.
2. **CEL Predicate Builder**: Converts inline tool permissions into Common Expression Language (CEL) predicates (e.g., `request.headers['x-mcp-toolname'] in ['get_weather']`) which Authorino natively evaluates against the user's claims.
3. **Tools Filter**: A broker-level hook (`tools_filter.go`) that intercepts `tools/list` requests. It ensures that downstream agents only see the specific tools they are authorized to execute, preventing unnecessary information disclosure.

## Design

For a deeper dive into the mapping logic, identity models, and sequence diagrams detailing the request flow through Envoy and Authorino, please see the [Design Document](docs/design/accesspolicy-design.md).

## Limitations

As a prototype, this currently focuses on validating the core architecture:
- Identity mapping is currently limited to OIDC sources in the builder logic.
- Kuadrant `AuthPolicy` types are stubbed locally to keep the prototype lightweight and avoid pulling in the full `kuadrant-operator` dependency graph.
