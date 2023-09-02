namespace Hyperar.OAuthCore.UnitTest.Provider.Inspectors
{
    using Hyperar.OauthCore.Framework;
    using Hyperar.OauthCore.Provider.Inspectors;
    using Xunit;

    [TestClass]
    public class XAuthValidationInspectorTests
    {
        public bool ValidateXAuthMode(string authMode)
        {
            return authMode == "client_auth";
        }

        public bool AuthenticateXAuthUsernameAndPassword(string username, string password)
        {
            return username == "username" && password == "password";
        }

        [TestMethod]
        public void EmptyModeThrows()
        {
            var context = new OAuthContext { XAuthMode = string.Empty };

            var inspector = new XAuthValidationInspector(this.ValidateXAuthMode, this.AuthenticateXAuthUsernameAndPassword);
            var ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.CreateAccessToken, context));
            Assert.AreEqual("The x_auth_mode parameter must be present", ex.Message);
        }

        [TestMethod]
        public void InvalidModeThrows()
        {
            var context = new OAuthContext { XAuthMode = "test_mode" };

            var inspector = new XAuthValidationInspector(this.ValidateXAuthMode, this.AuthenticateXAuthUsernameAndPassword);
            var ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.CreateAccessToken, context));
            Assert.AreEqual("The x_auth_mode parameter is invalid", ex.Message);
        }

        [TestMethod]
        public void EmptyUsernameThrows()
        {
            var context = new OAuthContext { XAuthMode = "client_auth" };

            var inspector = new XAuthValidationInspector(this.ValidateXAuthMode, this.AuthenticateXAuthUsernameAndPassword);
            var ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.CreateAccessToken, context));
            Assert.AreEqual("The x_auth_username parameter must be present", ex.Message);
        }

        [TestMethod]
        public void EmptyPasswordThrows()
        {
            var context = new OAuthContext { XAuthMode = "client_auth", XAuthUsername = "username" };

            var inspector = new XAuthValidationInspector(this.ValidateXAuthMode, this.AuthenticateXAuthUsernameAndPassword);
            var ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.CreateAccessToken, context));
            Assert.AreEqual("The x_auth_password parameter must be present", ex.Message);
        }

        [TestMethod]
        public void AuthenticationFailureThrows()
        {
            var context = new OAuthContext { XAuthMode = "client_auth", XAuthUsername = "Joe", XAuthPassword = "Bloggs" };

            var inspector = new XAuthValidationInspector(this.ValidateXAuthMode, this.AuthenticateXAuthUsernameAndPassword);
            var ex = Assert.ThrowsException<OAuthException>(() => inspector.InspectContext(ProviderPhase.CreateAccessToken, context));
            Assert.AreEqual("Authentication failed with the specified username and password", ex.Message);
        }

        [TestMethod]
        public void AuthenticationPasses()
        {
            var context = new OAuthContext { XAuthMode = "client_auth", XAuthUsername = "username", XAuthPassword = "password" };

            var inspector = new XAuthValidationInspector(this.ValidateXAuthMode, this.AuthenticateXAuthUsernameAndPassword);

            var exception = Record.Exception(() => inspector.InspectContext(ProviderPhase.CreateAccessToken, context));

            Assert.IsNull(exception);
        }
    }
}