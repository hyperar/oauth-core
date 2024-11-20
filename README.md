
Introduction
------------

The hyperar.OAuthCore project is a library for creating both OAuth consumers and providers on the .NET. It currently targets .NET 8, and is written in C#.

What is OAuth
-------------

The definition (from wikipedia) is:

> OAuth is an open protocol that allows users to share their private resources (e.g. photos, videos, contact lists) stored on one site with another site without having to hand out their username and password.

OAuth provides a standardised way to handle delegated Authentication through a series of exchanges, called an authentication flow.

What's supported
----------------

The hyperar.OAuthCore library currently supports building consumers (clients) and providers (servers) for both OAuth 1.0 and 1.0a.

The library is designed to be used in both web applications and thick client apps.
   
Additional Resources
--------------------

**OAuth Resources**

  - [Official OAuth website][2]
  - [OAuth wiki][3]
  - [A guide to how OAuth works - for beginners][4]


Downloads/Releases
------------------

You can download [Nuget][5].

  [1]: https://github.com/bittercoder/hyperar.OAuthCore/raw/master/artifacts/Oauth_diagram.png
  [2]: http://www.oauth.net/
  [3]: http://wiki.oauth.net/
  [4]: http://dotnetkicks.com/webservices/OAuth_for_Beginners
  [5]: https://www.nuget.org/packages/Hyperar.OAuthCore/

# Build status
[![Build status](https://ci.appveyor.com/api/projects/status/sfahewq9l1ipa942/branch/master?svg=true)](https://ci.appveyor.com/project/hyperar/oauth-core/branch/master)
