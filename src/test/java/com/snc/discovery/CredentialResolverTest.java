package com.snc.discovery;

import java.util.HashMap;
import java.util.Map;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class CredentialResolverTest {
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testCredentialResolver() {
        final CredentialResolver cr = new CredentialResolver();
        final Map<String, Object> args = new HashMap<String, Object>();

        args.put(CredentialResolver.ARG_ID, "2");
        args.put(CredentialResolver.ARG_TYPE, "windows");
        final Map<String, Object> result = cr.resolve(args);

        Assert.assertEquals("Rand0mPassw0rd.", result.get("pswd"));
    }

    @Test
    public void testCredentialResolverWithSSH() {
        final CredentialResolver cr = new CredentialResolver();
        final Map<String, Object> args = new HashMap<String, Object>();

        args.put(CredentialResolver.ARG_ID, "3");
        args.put(CredentialResolver.ARG_TYPE, "ssh_private_key");
        final Map<String, Object> result = cr.resolve(args);

        Assert.assertNull(result.get("pswd"));
        Assert.assertEquals("foobar", result.get("passphrase"));
    }

    @Test
    public void testCredentialResolverWithWindowsSecret() {
        final CredentialResolver cr = new CredentialResolver();
        final Map<String, Object> args = new HashMap<String, Object>();

        args.put(CredentialResolver.ARG_ID, "4");
        args.put(CredentialResolver.ARG_TYPE, "windows");
        final Map<String, Object> result = cr.resolve(args);

        Assert.assertEquals("Administrator", result.get("user"));
        Assert.assertEquals("v5W-e2fK7F-!XYqy)Wklo?5tw26j2Dz4", result.get("pswd"));
    }

    @Test
    public void testCredentialResolverWithStarMapping() {
        final CredentialResolver cr = new CredentialResolver();
        final Map<String, Object> args = new HashMap<String, Object>();

        args.put(CredentialResolver.ARG_ID, "4");
        args.put(CredentialResolver.ARG_TYPE, "nonexistent");
        final Map<String, Object> result = cr.resolve(args);

        Assert.assertEquals("Administrator", result.get("user"));
        Assert.assertEquals("v5W-e2fK7F-!XYqy)Wklo?5tw26j2Dz4", result.get("pswd"));
    }

    @Test
    public void testCredentialResolverWithGrantFile() {
        final CredentialResolver cr = new CredentialResolver("config-grant_file.xml",
                CredentialResolver.FIELD_MAPPINGS_JSON_PATH);
        final Map<String, Object> args = new HashMap<String, Object>();

        args.put(CredentialResolver.ARG_ID, "2");
        args.put(CredentialResolver.ARG_TYPE, "windows");
        final Map<String, Object> result = cr.resolve(args);

        Assert.assertEquals("Rand0mPassw0rd.", result.get("pswd"));
    }

    @Test
    public void testCredentialResolverWithTokenTxt() {
        final CredentialResolver cr = new CredentialResolver("config-token_txt.xml",
                CredentialResolver.FIELD_MAPPINGS_JSON_PATH);
        final Map<String, Object> args = new HashMap<String, Object>();

        args.put(CredentialResolver.ARG_ID, "2");
        args.put(CredentialResolver.ARG_TYPE, "windows");
        final Map<String, Object> result = cr.resolve(args);

        Assert.assertEquals("Rand0mPassw0rd.", result.get("pswd"));
    }
}
