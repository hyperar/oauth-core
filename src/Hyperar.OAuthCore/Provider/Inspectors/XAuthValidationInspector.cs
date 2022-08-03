namespace Hyperar.OauthCore.Provider.Inspectors
{
    using System;
    using Hyperar.OauthCore.Framework;

    public class XAuthValidationInspector : IContextInspector
    {
        private readonly Func<string, string, bool> _authenticateFunc;

        private readonly Func<string, bool> _validateModeFunc;

        public XAuthValidationInspector(Func<string, bool> validateModeFunc, Func<string, string, bool> authenticateFunc)
        {
            this._validateModeFunc = validateModeFunc;
            this._authenticateFunc = authenticateFunc;
        }

        public void InspectContext(ProviderPhase phase, IOAuthContext context)
        {
            if (phase != ProviderPhase.CreateAccessToken)
            {
                return;
            }

            var authMode = context.XAuthMode;
            if (string.IsNullOrEmpty(authMode))
            {
                throw Error.EmptyXAuthMode(context);
            }

            if (!this._validateModeFunc(authMode))
            {
                throw Error.InvalidXAuthMode(context);
            }

            var username = context.XAuthUsername;
            if (string.IsNullOrEmpty(username))
            {
                throw Error.EmptyXAuthUsername(context);
            }

            var password = context.XAuthPassword;
            if (string.IsNullOrEmpty(password))
            {
                throw Error.EmptyXAuthPassword(context);
            }

            if (!this._authenticateFunc(username, password))
            {
                throw Error.FailedXAuthAuthentication(context);
            }
        }
    }
}