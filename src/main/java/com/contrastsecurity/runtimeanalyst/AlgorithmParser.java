package com.contrastsecurity.runtimeanalyst;

import java.util.HashMap;
import java.util.Map;

/**
 * Parses cryptographic algorithm strings from Contrast observations
 * and extracts structured CBOM-compatible properties.
 */
public class AlgorithmParser {

    // Parsed algorithm properties
    private String rawAlgorithm;
    private String family;
    private String mode;
    private String padding;
    private String primitive;
    private int keySize;
    private int classicalSecurityLevel;
    private int nistQuantumSecurityLevel;
    private String oid;

    // OID mappings for common algorithms
    private static final Map<String, String> OID_MAP = new HashMap<>();
    static {
        // AES
        OID_MAP.put("AES-128-ECB", "2.16.840.1.101.3.4.1.1");
        OID_MAP.put("AES-128-CBC", "2.16.840.1.101.3.4.1.2");
        OID_MAP.put("AES-128-OFB", "2.16.840.1.101.3.4.1.3");
        OID_MAP.put("AES-128-CFB", "2.16.840.1.101.3.4.1.4");
        OID_MAP.put("AES-128-GCM", "2.16.840.1.101.3.4.1.6");
        OID_MAP.put("AES-192-ECB", "2.16.840.1.101.3.4.1.21");
        OID_MAP.put("AES-192-CBC", "2.16.840.1.101.3.4.1.22");
        OID_MAP.put("AES-192-GCM", "2.16.840.1.101.3.4.1.26");
        OID_MAP.put("AES-256-ECB", "2.16.840.1.101.3.4.1.41");
        OID_MAP.put("AES-256-CBC", "2.16.840.1.101.3.4.1.42");
        OID_MAP.put("AES-256-GCM", "2.16.840.1.101.3.4.1.46");
        // SHA
        OID_MAP.put("SHA-1", "1.3.14.3.2.26");
        OID_MAP.put("SHA-224", "2.16.840.1.101.3.4.2.4");
        OID_MAP.put("SHA-256", "2.16.840.1.101.3.4.2.1");
        OID_MAP.put("SHA-384", "2.16.840.1.101.3.4.2.2");
        OID_MAP.put("SHA-512", "2.16.840.1.101.3.4.2.3");
        OID_MAP.put("SHA3-224", "2.16.840.1.101.3.4.2.7");
        OID_MAP.put("SHA3-256", "2.16.840.1.101.3.4.2.8");
        OID_MAP.put("SHA3-384", "2.16.840.1.101.3.4.2.9");
        OID_MAP.put("SHA3-512", "2.16.840.1.101.3.4.2.10");
        // MD5
        OID_MAP.put("MD5", "1.2.840.113549.2.5");
        // RSA
        OID_MAP.put("RSA", "1.2.840.113549.1.1.1");
        OID_MAP.put("RSA-OAEP", "1.2.840.113549.1.1.7");
        OID_MAP.put("RSA-PSS", "1.2.840.113549.1.1.10");
        // EC
        OID_MAP.put("ECDSA", "1.2.840.10045.2.1");
        OID_MAP.put("ECDH", "1.3.132.1.12");
        // DES/3DES
        OID_MAP.put("DES", "1.3.14.3.2.7");
        OID_MAP.put("DESede", "1.2.840.113549.3.7");
        OID_MAP.put("3DES", "1.2.840.113549.3.7");
        // HMAC
        OID_MAP.put("HmacSHA1", "1.2.840.113549.2.7");
        OID_MAP.put("HmacSHA256", "1.2.840.113549.2.9");
        OID_MAP.put("HmacSHA384", "1.2.840.113549.2.10");
        OID_MAP.put("HmacSHA512", "1.2.840.113549.2.11");
        // Post-quantum
        OID_MAP.put("ML-KEM-512", "2.16.840.1.101.3.4.4.1");
        OID_MAP.put("ML-KEM-768", "2.16.840.1.101.3.4.4.2");
        OID_MAP.put("ML-KEM-1024", "2.16.840.1.101.3.4.4.3");
        OID_MAP.put("ML-DSA-44", "2.16.840.1.101.3.4.3.17");
        OID_MAP.put("ML-DSA-65", "2.16.840.1.101.3.4.3.18");
        OID_MAP.put("ML-DSA-87", "2.16.840.1.101.3.4.3.19");
    }

    public AlgorithmParser(String algorithm) {
        this.rawAlgorithm = algorithm;
        parse(algorithm);
    }

    private void parse(String algorithm) {
        if (algorithm == null || algorithm.isEmpty()) {
            return;
        }

        // Handle "ALGORITHM/MODE/PADDING" format (e.g., "AES/GCM/NoPadding")
        String[] parts = algorithm.split("/");
        String baseAlgo = parts[0].toUpperCase();

        // Extract mode and padding if present
        if (parts.length >= 2) {
            this.mode = parts[1].toLowerCase();
        }
        if (parts.length >= 3) {
            this.padding = normalizePadding(parts[2]);
        }

        // Parse the base algorithm
        parseBaseAlgorithm(baseAlgo);

        // JCA transformations for asymmetric ciphers conventionally include a "mode"
        // segment (e.g. "RSA/ECB/OAEPWithSHA-256AndMGF1Padding") that is a string-format
        // artifact, not a real block cipher mode - RSA/EC primitives don't have one.
        if (isAsymmetricPrimitive(this.primitive)) {
            this.mode = null;
        }

        // Look up OID
        this.oid = lookupOid();
    }

    private void parseBaseAlgorithm(String algo) {
        // Password-based encryption, e.g. "PBEWithMD5AndDES", "PBEWithHmacSHA256AndAES_128".
        // Must be checked first since these names contain "AES"/"DES"/"SHA" substrings that
        // would otherwise match those algorithms' own branches below.
        if (algo.startsWith("PBE")) {
            parsePbe(algo);
        }
        // AES variants
        else if (algo.startsWith("AES")) {
            this.family = "aes";
            this.primitive = isAuthenticatedMode() ? "ae" : "block-cipher";
            this.keySize = extractKeySize(algo, 128); // Default to 128 if not specified
            this.classicalSecurityLevel = this.keySize;
            this.nistQuantumSecurityLevel = calculateQuantumLevel(this.keySize, "symmetric");
        }
        // SHA variants
        else if (algo.startsWith("SHA")) {
            this.family = algo.contains("SHA3") ? "sha3" : "sha2";
            this.primitive = "hash";
            this.keySize = extractHashSize(algo);
            this.classicalSecurityLevel = this.keySize / 2; // Birthday attack
            this.nistQuantumSecurityLevel = calculateQuantumLevel(this.keySize, "hash");
        }
        // MD5
        else if (algo.equals("MD5")) {
            this.family = "md";
            this.primitive = "hash";
            this.keySize = 128;
            this.classicalSecurityLevel = 0; // Broken
            this.nistQuantumSecurityLevel = 0;
        }
        // RSA variants
        else if (algo.startsWith("RSA")) {
            this.family = "rsa";
            this.primitive = "pke";
            this.keySize = extractKeySize(algo, 2048);
            this.classicalSecurityLevel = calculateRsaSecurityLevel(this.keySize);
            this.nistQuantumSecurityLevel = 0; // Quantum vulnerable
        }
        // EC variants
        else if (algo.startsWith("EC") || algo.contains("ECDSA") || algo.contains("ECDH")) {
            this.family = "ec";
            if (algo.contains("DSA")) {
                this.primitive = "signature";
            } else if (algo.contains("DH")) {
                this.primitive = "kex";
            } else {
                this.primitive = "pke";
            }
            this.keySize = extractKeySize(algo, 256);
            this.classicalSecurityLevel = this.keySize / 2;
            this.nistQuantumSecurityLevel = 0; // Quantum vulnerable
        }
        // DES variants
        else if (algo.contains("DES")) {
            this.family = algo.contains("3DES") || algo.contains("DESEDE") ? "3des" : "des";
            this.primitive = "block-cipher";
            this.keySize = algo.contains("3DES") || algo.contains("DESEDE") ? 168 : 56;
            this.classicalSecurityLevel = this.keySize == 168 ? 112 : 0; // DES is broken
            this.nistQuantumSecurityLevel = 0;
        }
        // HMAC variants
        else if (algo.startsWith("HMAC")) {
            this.family = "hmac";
            this.primitive = "mac";
            this.keySize = extractHashSize(algo);
            this.classicalSecurityLevel = this.keySize;
            this.nistQuantumSecurityLevel = calculateQuantumLevel(this.keySize, "symmetric");
        }
        // Post-quantum algorithms
        else if (algo.contains("ML-KEM") || algo.contains("MLKEM")) {
            this.family = "ml-kem";
            this.primitive = "kem";
            this.keySize = extractKeySize(algo, 768);
            this.classicalSecurityLevel = mlKemSecurityLevel(this.keySize);
            this.nistQuantumSecurityLevel = mlKemQuantumLevel(this.keySize);
        }
        else if (algo.contains("ML-DSA") || algo.contains("MLDSA")) {
            this.family = "ml-dsa";
            this.primitive = "signature";
            this.keySize = extractKeySize(algo, 65);
            this.classicalSecurityLevel = mlDsaSecurityLevel(this.keySize);
            this.nistQuantumSecurityLevel = mlDsaQuantumLevel(this.keySize);
        }
        // Blowfish
        else if (algo.contains("BLOWFISH")) {
            this.family = "blowfish";
            this.primitive = "block-cipher";
            this.keySize = 128;
            this.classicalSecurityLevel = 128;
            this.nistQuantumSecurityLevel = 1;
        }
        // ChaCha20
        else if (algo.contains("CHACHA")) {
            this.family = "chacha";
            this.primitive = algo.contains("POLY") ? "ae" : "stream-cipher";
            this.keySize = 256;
            this.classicalSecurityLevel = 256;
            this.nistQuantumSecurityLevel = 5;
        }
        // Default/unknown
        else {
            this.family = algo.toLowerCase();
            this.primitive = "unknown";
            this.keySize = 0;
            this.classicalSecurityLevel = 0;
            this.nistQuantumSecurityLevel = 0;
        }
    }

    private void parsePbe(String algo) {
        this.family = "pbe";
        this.primitive = "block-cipher";
        if (algo.contains("AES")) {
            this.keySize = extractKeySize(algo, 128);
        } else if (algo.contains("3DES") || algo.contains("DESEDE")) {
            this.keySize = 168;
        } else if (algo.contains("DES")) {
            this.keySize = 56;
        } else {
            this.keySize = 0;
        }
        // PBE constructions from the legacy JCA providers (MD5/SHA-1 digest, DES/3DES
        // cipher) are broken regardless of nominal key size; only flag modern
        // AES-based PBE as having real security margin.
        boolean weakDigest = algo.contains("MD5") || algo.contains("SHA1") || algo.contains("SHA-1");
        boolean weakCipher = algo.contains("DES") && !algo.contains("AES");
        if (weakDigest || weakCipher) {
            this.classicalSecurityLevel = 0;
            this.nistQuantumSecurityLevel = 0;
        } else {
            this.classicalSecurityLevel = this.keySize;
            this.nistQuantumSecurityLevel = calculateQuantumLevel(this.keySize, "symmetric");
        }
    }

    private boolean isAsymmetricPrimitive(String primitive) {
        return "pke".equals(primitive) || "signature".equals(primitive)
            || "kex".equals(primitive) || "kem".equals(primitive);
    }

    private boolean isAuthenticatedMode() {
        return "gcm".equalsIgnoreCase(mode) ||
               "ccm".equalsIgnoreCase(mode) ||
               "eax".equalsIgnoreCase(mode);
    }

    private String normalizePadding(String pad) {
        if (pad == null) return null;
        String p = pad.toLowerCase();
        if (p.contains("nopadding") || p.equals("none")) return "none";
        if (p.contains("pkcs5") || p.contains("pkcs7")) return "pkcs7";
        if (p.contains("oaep")) return "oaep";
        if (p.contains("pkcs1")) return "pkcs1v15";
        return p;
    }

    private int extractKeySize(String algo, int defaultSize) {
        // Try to find a number in the algorithm name
        StringBuilder num = new StringBuilder();
        for (char c : algo.toCharArray()) {
            if (Character.isDigit(c)) {
                num.append(c);
            } else if (num.length() > 0) {
                break;
            }
        }
        if (num.length() > 0) {
            int size = Integer.parseInt(num.toString());
            // Normalize common sizes
            if (size == 128 || size == 192 || size == 256 || size == 512 ||
                size == 1024 || size == 2048 || size == 3072 || size == 4096) {
                return size;
            }
            // ML-KEM sizes
            if (size == 512 || size == 768 || size == 1024) {
                return size;
            }
            // ML-DSA sizes
            if (size == 44 || size == 65 || size == 87) {
                return size;
            }
        }
        return defaultSize;
    }

    private int extractHashSize(String algo) {
        if (algo.contains("512")) return 512;
        if (algo.contains("384")) return 384;
        if (algo.contains("256")) return 256;
        if (algo.contains("224")) return 224;
        if (algo.contains("160") || algo.contains("1")) return 160;
        return 256; // Default
    }

    private int calculateQuantumLevel(int bits, String type) {
        // NIST quantum security levels based on Grover's algorithm impact
        // Symmetric: halved effective security
        // Hash: also halved for collision resistance
        int effectiveBits = bits / 2;
        if (effectiveBits >= 256) return 5;
        if (effectiveBits >= 192) return 4;
        if (effectiveBits >= 128) return 3;
        if (effectiveBits >= 96) return 2;
        if (effectiveBits >= 64) return 1;
        return 0;
    }

    private int calculateRsaSecurityLevel(int keySize) {
        // Approximate classical security level for RSA
        if (keySize >= 15360) return 256;
        if (keySize >= 7680) return 192;
        if (keySize >= 3072) return 128;
        if (keySize >= 2048) return 112;
        if (keySize >= 1024) return 80;
        return 0;
    }

    private int mlKemSecurityLevel(int param) {
        switch (param) {
            case 512: return 128;
            case 768: return 192;
            case 1024: return 256;
            default: return 0;
        }
    }

    private int mlKemQuantumLevel(int param) {
        switch (param) {
            case 512: return 1;
            case 768: return 3;
            case 1024: return 5;
            default: return 0;
        }
    }

    private int mlDsaSecurityLevel(int param) {
        switch (param) {
            case 44: return 128;
            case 65: return 192;
            case 87: return 256;
            default: return 0;
        }
    }

    private int mlDsaQuantumLevel(int param) {
        switch (param) {
            case 44: return 2;
            case 65: return 3;
            case 87: return 5;
            default: return 0;
        }
    }

    private String lookupOid() {
        // Try exact match first
        if (OID_MAP.containsKey(rawAlgorithm)) {
            return OID_MAP.get(rawAlgorithm);
        }

        // Try normalized key (family + keySize + mode)
        String normalizedKey = family.toUpperCase();
        if (keySize > 0) {
            normalizedKey += "-" + keySize;
        }
        if (mode != null) {
            normalizedKey += "-" + mode.toUpperCase();
        }
        if (OID_MAP.containsKey(normalizedKey)) {
            return OID_MAP.get(normalizedKey);
        }

        // Try family only
        if (OID_MAP.containsKey(family.toUpperCase())) {
            return OID_MAP.get(family.toUpperCase());
        }

        return null;
    }

    // Getters
    public String getRawAlgorithm() { return rawAlgorithm; }
    public String getFamily() { return family; }
    public String getMode() { return mode; }
    public String getPadding() { return padding; }
    public String getPrimitive() { return primitive; }
    public int getKeySize() { return keySize; }
    public int getClassicalSecurityLevel() { return classicalSecurityLevel; }
    public int getNistQuantumSecurityLevel() { return nistQuantumSecurityLevel; }
    public String getOid() { return oid; }

    public boolean isQuantumVulnerable() {
        return nistQuantumSecurityLevel == 0;
    }

    public String getNormalizedName() {
        StringBuilder sb = new StringBuilder();
        sb.append(family.toUpperCase());
        if (keySize > 0) {
            sb.append("-").append(keySize);
        }
        if (mode != null) {
            sb.append("-").append(mode.toUpperCase());
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return String.format("Algorithm[%s: family=%s, primitive=%s, keySize=%d, " +
                           "classicalSecurity=%d, quantumLevel=%d, oid=%s]",
                           rawAlgorithm, family, primitive, keySize,
                           classicalSecurityLevel, nistQuantumSecurityLevel, oid);
    }
}
