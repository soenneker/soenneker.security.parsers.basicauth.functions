using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Azure.Functions.Worker.Http;

namespace Soenneker.Security.Parsers.BasicAuth.Functions;

/// <summary>
/// Parses HTTP Basic credentials from Azure Functions requests into spans backed by a caller-released pooled buffer.
/// </summary>
public static class BasicAuthParser
{
    // Optional sanity cap to avoid giant headers (8KB of Base64 ~ 6KB bytes)
    private const int _maxBase64Chars = 8 * 1024;

    /// <summary>
    /// Attempts to decode Basic authentication credentials from the request Authorization header.
    /// </summary>
    /// <param name="request">request that defines the request to send.</param>
    /// <param name="username">Receives the decoded username when parsing succeeds.</param>
    /// <param name="password">Receives the decoded password when parsing succeeds.</param>
    /// <param name="charBufferToClear">Receives the rented character buffer on success. Pass it to <see cref="Clear"/> exactly once after using the spans.</param>
    /// <returns>true if valid Basic credentials were decoded and assigned; otherwise, false.</returns>
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
        char[]? rentedChars = null;

        try
        {
            if (!Convert.TryFromBase64Chars(b64, bytes, out bytesWritten) || bytesWritten == 0)
                return false;

            int maxChars = Encoding.UTF8.GetMaxCharCount(bytesWritten);
            rentedChars = ArrayPool<char>.Shared.Rent(maxChars);
            int charsWritten = Encoding.UTF8.GetChars(bytes, 0, bytesWritten, rentedChars, 0);

            Span<char> span = rentedChars.AsSpan(0, charsWritten);
            int colon = span.IndexOf(':');
            if (colon <= 0 || colon == span.Length - 1)
                return false;

            username = span.Slice(0, colon);
            password = span.Slice(colon + 1);
            charBufferToClear = rentedChars;
            rentedChars = null;
            return true;
        }
        finally
        {
            if (rentedChars is not null)
            {
                Array.Clear(rentedChars, 0, rentedChars.Length);
                ArrayPool<char>.Shared.Return(rentedChars);
            }

            CryptographicOperations.ZeroMemory(bytes.AsSpan(0, bytesWritten));
            ArrayPool<byte>.Shared.Return(bytes);
        }
    }

    /// <summary>
    /// Zeros and returns a character buffer received from <see cref="TryReadBasicCredentials"/>.
    /// </summary>
    /// <param name="charBuffer">The rented buffer to clear and return, or <see langword="null"/>.</param>
    public static void Clear(char[]? charBuffer)
    {
        if (charBuffer is null)
            return;

        Array.Clear(charBuffer, 0, charBuffer.Length);
        ArrayPool<char>.Shared.Return(charBuffer);
    }
}
