namespace Hyperar.OAuthCore.Utility
{
    using System;

    public static class HttpMethodUtility
    {
        public static HttpMethod ToHttpMethod(this string value)
        {
            return value.ToLower() switch
            {
                "connect" => HttpMethod.Connect,
                "delete" => HttpMethod.Delete,
                "get" => HttpMethod.Get,
                "head" => HttpMethod.Head,
                "options" => HttpMethod.Options,
                "patch" => HttpMethod.Patch,
                "post" => HttpMethod.Post,
                "put" => HttpMethod.Put,
                "trace" => HttpMethod.Trace,
                _ => throw new ArgumentOutOfRangeException(nameof(value))
            };
        }
    }
}
