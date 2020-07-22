Thycotic Secret Server ServiceNow MID Server Credential Resolver
================================================================

Overview
--------

This jar contains an implementation of `com.snc.discovery.CredentialResolver` that enables ServiceNow to use Thycotic Secret Server secrets as Discovery Credentials.

The `CredentialResolver` uses the Secret Server [REST API](https://updates.thycotic.net/secretserver/restapiguide/10.6/index.html) to request secrets, and *field-mappings* to map the Secret Server secret fields to ServiceNow Discovery Credential-type fields.

The `CredentialResolver` has two modes of operation with respect to the OAuth2 access_token:
1. Using `ext.tss.oauth2.grant_file` to load an OAuth2 access_token stored in a file or,
2. Using `ext.tss.oauth2.username` and `ext.tss.oauth2.password` to submit an OAuth2 Access Grant Request using the OAuth2 `password_grant` `grant_type` just-in-time.

Configuration
-------------

1. Upload the jar to ServiceNow by following these [directions](https://docs.servicenow.com/bundle/london-servicenow-platform/page/product/credentials/concept/external_cred_storage_configuration.html#t_ImportJARResolveCredent).
2. Add the following to the target MID Server(s) `config.xml`:

   To request an OAuth2 Access Grant from the server:

       <parameter name="ext.tss.url" value="https://your-secert-server.com" />
       <parameter name="ext.tss.oauth2.username" value="snmiduser" />
       <parameter name="ext.tss.oauth2.password" value="Passw0rd!" />
       <parameter name="ext.tss.allow.self_signed_certificates" value="false" />

   To use an OAuth2 Access Grant stored in a file:

       <parameter name="ext.tss.url" value="https://your-secert-server.com" />
       <parameter name="ext.tss.oauth2.grant_file" value="/path/to/oauth2_grant.json" />
       <!-- just the token text also works
       <parameter name="ext.tss.oauth2.grant_file" value="/path/to/token.txt" />
       -->
       <parameter name="ext.tss.allow.self_signed_certificates" value="false" />

   Note that the OAuth2 user used to obtain the `access_token` must be a Secret Server *Application User* with "View" access on the secret(s) being used as Credentials in ServiceNow Discovery.

Usage
-----

When adding a Credential in ServiceNow, check *External credential store* and enter the Id of the Thycotic Secret Server secret to which this credential corresponds, in the *Credential ID* field.


Note
----

A field-mapping must be declared for the selected credential-type in `tss-credential-resolver-field-mappings.json`, however, a '*' mapping is included with username => user and password => pswd, as defaults. See the Javadoc for additional details.

To use an `access_token` stored in a file, create a Scheduled Task that runs a script that recreates the file prior to the expiration of the token stored in the current one. See example code in  `Get-OAuth2AccessToken.ps1`.
