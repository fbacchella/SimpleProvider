package fr.loghub.simpleprovider;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class SubKeyStore implements KeyStore.LoadStoreParameter {

    final Set<URI> substores = new LinkedHashSet<>();
    final Set<URI> subtruststores = new LinkedHashSet<>();

    public void addSubStore(String substore) {
        substores.add(fileUri(substore));
    }

    public void addSubTrustStore(String substore) {
        subtruststores.add(fileUri(substore));
    }

    public void addSubStore(URI substore) {
        substores.add(substore);
    }

    public void addSubTrustStore(URI substore) {
        subtruststores.add(substore);
    }

    @Override
    public KeyStore.ProtectionParameter getProtectionParameter() {
        return MultiKeyStoreSpi.EMPTYPROTECTION;
    }

    Map<String, String> parseQuery(URI uri) {
        String query = uri.getRawQuery();
        if (query == null || query.isEmpty()) {
            return Map.of();
        }

        Map<String, String> result = new LinkedHashMap<>();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf('=');
            String key;
            String value;
            if (idx >= 0) {
                key = pair.substring(0, idx);
                value = pair.substring(idx + 1);
            } else {
                key = pair;
                value = "";
            }

            key = URLDecoder.decode(key, StandardCharsets.UTF_8);
            value = URLDecoder.decode(value, StandardCharsets.UTF_8);

            result.put(key, value);
        }

        return result;
    }

    /**
     * Parse a source and return a URI, but with specialisation to file.<br>
     * If no scheme is defined, it defaults to a file scheme, where standard URI default to no scheme<br>
     * If a relative path is given, with or without a file scheme, it's resolved to the absolute path, instead of a
     * scheme specific part in the standard URI.<br>
     * If the scheme is an explicit <code>file</code>, the query (<code>?...</code>) and the fragment (<code>#...</code>)
     * are preserved, so they can be used as optional parameter to load content. If no scheme is defined, the path is
     * used as is. So <code>file:/example?q</code> will resolve to the file <code>/example</code> with query
     * <code>q</code>, and <code>/example?q</code> will resolve to the file <code>/example?q</code><br>
     * Of course, any other URI is kept unchanged
     * The URI should not be used directly with {@link Paths#get(URI)} as it preserves any eventual query
     * or fragment and Paths will fail. Instead, one should use <code>Paths.get(Helpers.GeneralizedURI(...).getPath())</code>.<br>
     * This method aims to be used as <code>Helpers.GeneralizedURI(...).toURL().openStream()</code>.
     * @param source The path or URI to parse.
     * @return {@link IllegalArgumentException} if the URI can’t be resolved.
     */
    public URI fileUri(String source) {
        return fileUri(source, Paths.get(""));
    }

    /**
     * Parse a source and return a URI, but with specialisation to file.<br>
     * If no scheme is defined, it defaults to a file scheme, where standard URI default to no scheme<br>
     * If a relative path is given, with or without a file scheme, it's resolved to the absolute path, instead of a
     * scheme specific part in the standard URI.<br>
     * If the scheme is an explicit <code>file</code>, the query (<code>?...</code>) and the fragment (<code>#...</code>)
     * are preserved, so they can be used as optional parameter to load content. If no scheme is defined, the path is
     * used as is. So <code>file:/example?q</code> will resolve to the file <code>/example</code> with query
     * <code>q</code>, and <code>/example?q</code> will resolve to the file <code>/example?q</code><br>
     * Of course, any other URI is kept unchanged
     * The URI should not be used directly with {@link Paths#get(URI)} as it preserves any eventual query
     * or fragment and Paths will fail. Instead, one should use <code>Paths.get(Helpers.GeneralizedURI(...).getPath())</code>.<br>
     * This method aims to be used as <code>Helpers.GeneralizedURI(...).toURL().openStream()</code>.
     * @param source The path or URI to parse.
     * @param root the root to resolve relatives path
     * @return {@link IllegalArgumentException} if the URI can’t be resolved.
     */
    public URI fileUri(String source, Path root) {
        URI sourceURI;
        try {
            sourceURI = URI.create(source).normalize();
        } catch (IllegalArgumentException ex) {
            // Invalid URI, will be tried as a Path
            sourceURI = null;
        }
        try {
            URI newURI;
            if (sourceURI == null || sourceURI.getScheme() == null) {
                newURI = root.resolve(source).toUri();
            } else if ("file".equals(sourceURI.getScheme()) && sourceURI.getHost() != null) {
                // Written as file://relativepath, mistake the first part as a host
                String newPath = sourceURI.getHost() + ((sourceURI.getPath() == null || sourceURI.getPath().isEmpty()) ? "" : "/" + sourceURI.getPath());
                newURI = new URI("file", null, "//" + root.resolve(newPath).toAbsolutePath(),
                        sourceURI.getQuery(), sourceURI.getFragment());
            } else if ("file".equals(sourceURI.getScheme()) && sourceURI.getSchemeSpecificPart() != null && sourceURI.getPath() == null) {
                // If file is a relative URI, it's not resolved, and it's stored in the SSP
                String uriBuffer = "file://" + root.toAbsolutePath() + File.separator + sourceURI.getSchemeSpecificPart();
                // intermediate URI because URI.normalize() is not smart enough
                URI tempUri = URI.create(uriBuffer);
                newURI = new URI("file", tempUri.getAuthority(), "//" + root.resolve(tempUri.getPath()).normalize(), tempUri.getQuery(), sourceURI.getFragment());
            } else if ("file".equals(sourceURI.getScheme())) {
                newURI = new URI("file", sourceURI.getAuthority(), "//" + root.resolve(sourceURI.getPath()), sourceURI.getQuery(), sourceURI.getFragment());
            } else {
                newURI = sourceURI;
            }
            return newURI.normalize();
        } catch (URISyntaxException | FileSystemNotFoundException ex) {
            throw new IllegalArgumentException("Invalid generalized source path: " + ex.getMessage(), ex);
        }
    }

}
