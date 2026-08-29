[![](https://img.shields.io/nuget/v/soenneker.security.parsers.basicauth.functions.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.security.parsers.basicauth.functions/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.security.parsers.basicauth.functions/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.security.parsers.basicauth.functions/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.security.parsers.basicauth.functions.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.security.parsers.basicauth.functions/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.security.parsers.basicauth.functions/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.security.parsers.basicauth.functions/actions/workflows/codeql.yml)

# Soenneker.Security.Parsers.BasicAuth.Functions

A library for basic authorization parsing.

## Install

```bash
dotnet add package Soenneker.Security.Parsers.BasicAuth.Functions
```

## Quick start

```csharp
using Soenneker.Security.Parsers.BasicAuth.Functions;

var result = BasicAuthParser.TryReadBasicCredentials(/* supply request */ default!, /* supply username */ default!, /* supply password */ default!, /* supply charBufferToClear */ default!);
```

Attempts to decode Basic authentication credentials from the request Authorization header.

## What you get

- `BasicAuthParser` — A library for basic authorization parsing.

## API at a glance

| API | What it does | Result / important behavior |
| --- | --- | --- |
| `BasicAuthParser.TryReadBasicCredentials(request, username, password, charBufferToClear)` | Attempts to decode Basic authentication credentials from the request Authorization header. | true if valid Basic credentials were decoded and assigned; otherwise, false. |
| `BasicAuthParser.Clear(charBuffer)` | Removes all entries managed by the Basic Auth Parser. | Returns no value; the requested change is complete when the method returns. |
