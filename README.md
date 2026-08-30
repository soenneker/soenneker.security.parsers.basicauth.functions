[![](https://img.shields.io/nuget/v/soenneker.security.parsers.basicauth.functions.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.security.parsers.basicauth.functions/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.security.parsers.basicauth.functions/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.security.parsers.basicauth.functions/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.security.parsers.basicauth.functions.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.security.parsers.basicauth.functions/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.security.parsers.basicauth.functions/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.security.parsers.basicauth.functions/actions/workflows/codeql.yml)

# Soenneker.Security.Parsers.BasicAuth.Functions

A low-allocation HTTP Basic credential parser for .NET isolated Azure Functions.

## Installation

```bash
dotnet add package Soenneker.Security.Parsers.BasicAuth.Functions
```

## Usage

The returned spans point into a pooled character buffer. Return that buffer in a `finally` block after the last credential comparison:

```csharp
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Soenneker.Security.Parsers.BasicAuth.Functions;

[Function("ProtectedEndpoint")]
public HttpResponseData Run(
    [HttpTrigger(AuthorizationLevel.Anonymous, "get")] HttpRequestData request)
{
    char[]? credentialBuffer = null;

    try
    {
        if (!BasicAuthParser.TryReadBasicCredentials(
                request,
                out ReadOnlySpan<char> username,
                out ReadOnlySpan<char> password,
                out credentialBuffer))
        {
            return request.CreateResponse(HttpStatusCode.Unauthorized);
        }

        bool usernameMatches = username.SequenceEqual(_configuredUsername);
        byte[] suppliedPassword = Encoding.UTF8.GetBytes(password);

        try
        {
            bool passwordMatches = CryptographicOperations.FixedTimeEquals(
                suppliedPassword,
                _configuredPasswordUtf8);

            return request.CreateResponse(
                usernameMatches && passwordMatches
                    ? HttpStatusCode.OK
                    : HttpStatusCode.Unauthorized);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(suppliedPassword);
        }
    }
    finally
    {
        BasicAuthParser.Clear(credentialBuffer);
    }
}
```

Prepare `_configuredPasswordUtf8` outside the request path and protect it like the original secret. Prefer a password hasher or identity provider when the endpoint authenticates user passwords rather than a fixed service credential.

## Parsing behavior

- Reads the first `Authorization` header value and accepts the `Basic` scheme case-insensitively.
- Rejects missing or malformed Base64, headers above 8 KiB, and decoded credentials without a non-empty username and password separated by the first colon.
- Allows additional colons in the password.
- Returns spans instead of immutable username/password strings.
- On success, transfers one rented character buffer to the caller. Call `BasicAuthParser.Clear` exactly once after using the spans.
- On failure, clears and returns any rented buffer and leaves the returned buffer value `null`.

Basic authentication is encoding, not encryption. Use it only over HTTPS, never log the header or decoded credentials, and protect the endpoint with suitable rate limiting and secret rotation.
