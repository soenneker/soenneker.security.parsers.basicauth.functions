using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Azure.Functions.Worker.Http;

namespace Soenneker.Security.Parsers.BasicAuth.Functions;

/// <summary>
/// A library for basic authorization parsing
/// </summary>
public static class BasicAuthParser
{
    // Optional sanity cap to avoid giant headers (8KB of Base64 ~ 6KB bytes)
    private const int _maxBase64Chars = 8 * 1024;

    public static bool TryReadBasicCredentials(HttpRequestData request, out ReadOnlySpan<char> username, out ReadOnlySpan<char> password,
        out char[]? charBufferToClear)
    {
        username = default;
        password = default;
        charBufferToClear = null;

        if (!request.Headers.TryGetValues("Authorization", out IEnumerable<string>? values))
            return false;

        string? value = null;

        foreach (string v in values)
        {
            value = v;
            break;
        } // first value only

        if (value is null)
            return false;

        return TryParseFromAuthorizationHeader(value, out username, out password, out charBufferToClear);
    }

    private static bool TryParseFromAuthorizationHeader(string? authorizationValue, out ReadOnlySpan<char> username, out ReadOnlySpan<char> password,
        out char[]? charBufferToClear)
    {
        username = default;
        password = default;
        charBufferToClear = null;

        if (authorizationValue is null || !authorizationValue.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return false;

        ReadOnlySpan<char> b64 = authorizationValue.AsSpan(6).Trim();
        if (b64.Length == 0 || b64.Length > _maxBase64Chars)
            return false;

        int maxBytes = b64.Length * 3 / 4 + 3;
        byte[] bytes = ArrayPool<byte>.Shared.Rent(maxBytes);
        int bytesWritten = 0;

        try
        {
            if (!Convert.TryFromBase64Chars(b64, bytes, out bytesWritten) || bytesWritten == 0)
                return false;

            int maxChars = Encoding.UTF8.GetMaxCharCount(bytesWritten);
            charBufferToClear = ArrayPool<char>.Shared.Rent(maxChars);
            int charsWritten = Encoding.UTF8.GetChars(bytes, 0, bytesWritten, charBufferToClear, 0);

            Span<char> span = charBufferToClear.AsSpan(0, charsWritten);
            int colon = span.IndexOf(':');
            if (colon <= 0 || colon == span.Length - 1)
                return false;

            username = span.Slice(0, colon);
            password = span.Slice(colon + 1);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes.AsSpan(0, bytesWritten));
            ArrayPool<byte>.Shared.Return(bytes);
        }
    }

    public static void Clear(char[]? charBuffer)
    {
        if (charBuffer is null)
            return;

        Array.Clear(charBuffer, 0, charBuffer.Length);
        ArrayPool<char>.Shared.Return(charBuffer);
    }
}