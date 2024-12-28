namespace Hyperar.OAuthCore.UnitTest.Provider.Inspectors
{
    using Hyperar.OAuthCore.Framework;
    using Hyperar.OAuthCore.Provider.Inspectors;
    using Xunit;

    [TestClass]
    public class XAuthValidationInspectorTests
    {
        public static bool AuthenticateXAuthUsernameAndPassword(string username, string password)
        {
            return username == "username" && password == "password";
        }

        public static bool ValidateXAuthMode(string authMode)
        {
            return authMode == "client_auth";
        }

        [TestMethod]
        public void AuthenticationFailureThrows()
        {
            OAuthContext context = new OAuthContext { XAuthMode = "client_auth", XAuthUsername = "Joe", XAuthPassword = "Bloggs" };

            XAuthValidationInspector inspector = new XAuthValidationInspector(ValidateXAuthMode, AuthenticateXAuthUsernameAndPassword);
            OAuthException ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.CreateAccessToken, context));
            Assert.AreEqual("Authentication failed with the specified username and password", ex.Message);
        }

        [TestMethod]
        public void AuthenticationPasses()
        {
            OAuthContext context = new OAuthContext { XAuthMode = "client_auth", XAuthUsername = "username", XAuthPassword = "password" };

            XAuthValidationInspector inspector = new XAuthValidationInspector(ValidateXAuthMode, AuthenticateXAuthUsernameAndPassword);

            Exception exception = Record.Exception(() => inspector.InspectContext(ProviderPhase.CreateAccessToken, context));

            Assert.IsNull(exception);
        }

        [TestMethod]
        public void EmptyModeThrows()
        {
            OAuthContext context = new OAuthContext { XAuthMode = string.Empty };

            XAuthValidationInspector inspector = new XAuthValidationInspector(ValidateXAuthMode, AuthenticateXAuthUsernameAndPassword);
            OAuthException ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.CreateAccessToken, context));
            Assert.AreEqual("The x_auth_mode parameter must be present", ex.Message);
        }

        [TestMethod]
        public void EmptyPasswordThrows()
        {
            OAuthContext context = new OAuthContext { XAuthMode = "client_auth", XAuthUsername = "username" };

            XAuthValidationInspector inspector = new XAuthValidationInspector(ValidateXAuthMode, AuthenticateXAuthUsernameAndPassword);
            OAuthException ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.CreateAccessToken, context));
            Assert.AreEqual("The x_auth_password parameter must be present", ex.Message);
        }

        [TestMethod]
        public void EmptyUsernameThrows()
        {
            OAuthContext context = new OAuthContext { XAuthMode = "client_auth" };

            XAuthValidationInspector inspector = new XAuthValidationInspector(ValidateXAuthMode, AuthenticateXAuthUsernameAndPassword);
            OAuthException ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.CreateAccessToken, context));
            Assert.AreEqual("The x_auth_username parameter must be present", ex.Message);
        }

        [TestMethod]
        public void InvalidModeThrows()
        {
            OAuthContext context = new OAuthContext { XAuthMode = "test_mode" };

            XAuthValidationInspector inspector = new XAuthValidationInspector(ValidateXAuthMode, AuthenticateXAuthUsernameAndPassword);
            OAuthException ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.CreateAccessToken, context));
            Assert.AreEqual("The x_auth_mode parameter is invalid", ex.Message);
        }
    }
}