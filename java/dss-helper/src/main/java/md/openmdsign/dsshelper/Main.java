package md.openmdsign.dsshelper;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * Long-running stdio JSON helper driving EU DSS for standalone XAdES creation
 * via two-step external signing.
 *
 * <p>Protocol: line-delimited JSON on stdin/stdout. One request object per line,
 * one response object per line. The PKCS#11 PIN and private key never enter this
 * JVM; {@code getDataToSign} returns the data-to-be-signed, the Go side signs it
 * on the token, and {@code signDocument} assembles the final XAdES around the
 * returned signature value.
 *
 * <p>Ops:
 * <ul>
 *   <li>{@code getDataToSign} -> {@code {"ok":true,"dtbs":"<base64>"}}</li>
 *   <li>{@code signDocument}  -> {@code {"ok":true,"xml":"<base64>"}}</li>
 *   <li>{@code validate}      -> {@code {"ok":true,"indication":..,"subIndication":..}}</li>
 *   <li>{@code ping}          -> {@code {"ok":true,"pong":true}}</li>
 * </ul>
 * Any failure yields {@code {"ok":false,"error":"<message>"}} and never aborts
 * the process (so a caller may retry a fresh signing session without a relaunch).
 */
public final class Main {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // State carried across the two-step exchange so signDocument reproduces the
    // exact SignedInfo that getDataToSign returned (identical signing date, refs).
    private XAdESSignatureParameters params;
    private DSSDocument document;
    private XAdESService service;
    private DigestAlgorithm digestAlgo;

    public static void main(String[] args) throws Exception {
        // stdout carries the JSON protocol ONLY; route any stray library logging
        // that targets System.out to stderr instead.
        PrintStream out = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), true, "UTF-8");
        new Main().run(new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)), out);
    }

    void run(BufferedReader in, PrintStream out) throws Exception {
        String line;
        while ((line = in.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            ObjectNode resp = MAPPER.createObjectNode();
            try {
                JsonNode req = MAPPER.readTree(line);
                String op = text(req, "op", "");
                switch (op) {
                    case "ping" -> {
                        resp.put("ok", true);
                        resp.put("pong", true);
                    }
                    case "getDataToSign" -> handleGetDataToSign(req, resp);
                    case "signDocument" -> handleSignDocument(req, resp);
                    case "validate" -> handleValidate(req, resp);
                    default -> {
                        resp.put("ok", false);
                        resp.put("error", "unknown op: " + op);
                    }
                }
            } catch (Throwable t) {
                resp.removeAll();
                resp.put("ok", false);
                resp.put("error", describe(t));
            }
            out.println(MAPPER.writeValueAsString(resp));
            out.flush();
        }
    }

    private void handleGetDataToSign(JsonNode req, ObjectNode resp) throws Exception {
        SignatureLevel level = SignatureLevel.valueOf(reqText(req, "level"));
        SignaturePackaging packaging = SignaturePackaging.valueOf(reqText(req, "packaging"));
        this.digestAlgo = DigestAlgorithm.valueOf(text(req, "digestAlgo", "SHA256"));

        CertificateToken signingCert = new CertificateToken(parseCert(reqText(req, "signingCertB64")));

        byte[] fileBytes = Base64.getDecoder().decode(reqText(req, "fileB64"));
        String referencedName = reqText(req, "referencedName");
        String mimeType = text(req, "mimeType", "application/octet-stream");
        String signingTime = reqText(req, "signingTime"); // ISO-8601 instant, e.g. 2026-07-18T10:00:00Z
        boolean en319132 = req.has("en319132") && req.get("en319132").asBoolean();

        XAdESSignatureParameters p = new XAdESSignatureParameters();
        p.setSignatureLevel(level);
        p.setSignaturePackaging(packaging);
        p.setDigestAlgorithm(this.digestAlgo);
        // Old TS 101 903 v1.3.2 SigningCertificate (v1), NOT the EN 319132
        // SigningCertificateV2 -- matches the vendor sample.
        p.setEn319132(en319132);
        p.setSigningCertificate(signingCert);
        // KeyInfo/X509Data carries the signer certificate ONLY (no chain), per
        // docs/profile-spec.md sec 1.
        p.setCertificateChain(Collections.singletonList(signingCert));
        p.setSigningCertificateDigestMethod(this.digestAlgo);
        p.bLevel().setSigningDate(Date.from(Instant.parse(signingTime)));

        // Canonicalization of SignedInfo: plain C14N 1.0 for detached (no
        // comments); the WithComments variant for enveloping (vendor quirk).
        if (packaging == SignaturePackaging.DETACHED) {
            p.setSignedInfoCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        } else {
            p.setSignedInfoCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
        }

        // The detached reference URI is derived from the document name. Go passes
        // referencedName = "file:/<basename>" so the reference becomes
        // URI="file:/<basename>" exactly, with digest over the raw file bytes.
        this.document = new InMemoryDocument(fileBytes, referencedName);

        CertificateVerifier cv = new CommonCertificateVerifier();
        XAdESService svc = new XAdESService(cv);
        if (level == SignatureLevel.XAdES_BASELINE_T || level == SignatureLevel.XAdES_T
                || level == SignatureLevel.XAdES_BASELINE_LT || level == SignatureLevel.XAdES_BASELINE_LTA) {
            String tsaUrl = reqText(req, "tsaUrl");
            OnlineTSPSource tsp = new OnlineTSPSource(tsaUrl);
            tsp.setDataLoader(new TimestampDataLoader());
            svc.setTspSource(tsp);
            // The MoldSign TSA (MDQTSA) accepts a SHA-256 request digest and
            // rejects DSS's default (SHA-512) with PKIFailureInfo 0x80. Pin the
            // SignatureTimeStamp digest to the profile digest, and canonicalize
            // the timestamped SignatureValue with plain C14N 1.0 (no comments).
            eu.europa.esig.dss.xades.XAdESTimestampParameters tsParams = p.getSignatureTimestampParameters();
            tsParams.setDigestAlgorithm(this.digestAlgo);
            tsParams.setCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
        }
        this.service = svc;
        this.params = p;

        ToBeSigned tbs = svc.getDataToSign(this.document, p);
        resp.put("ok", true);
        resp.put("dtbs", Base64.getEncoder().encodeToString(tbs.getBytes()));
    }

    private void handleSignDocument(JsonNode req, ObjectNode resp) throws Exception {
        if (this.params == null || this.document == null || this.service == null) {
            throw new IllegalStateException("signDocument called before getDataToSign");
        }
        byte[] sigValue = Base64.getDecoder().decode(reqText(req, "signatureValue"));
        SignatureAlgorithm alg = SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.RSA, this.digestAlgo);
        SignatureValue sv = new SignatureValue(alg, sigValue);

        DSSDocument signed = this.service.signDocument(this.document, this.params, sv);
        byte[] xml;
        try (InputStream is = signed.openStream()) {
            xml = is.readAllBytes();
        }
        resp.put("ok", true);
        resp.put("xml", Base64.getEncoder().encodeToString(xml));
    }

    private void handleValidate(JsonNode req, ObjectNode resp) throws Exception {
        byte[] xml = Base64.getDecoder().decode(reqText(req, "xmlB64"));
        DSSDocument doc = new InMemoryDocument(xml, "signature.xml");
        SignedDocumentValidator v = SignedDocumentValidator.fromDocument(doc);
        v.setCertificateVerifier(new CommonCertificateVerifier());

        if (req.hasNonNull("detachedFileB64")) {
            byte[] f = Base64.getDecoder().decode(req.get("detachedFileB64").asText());
            String name = text(req, "detachedName", "detached");
            List<DSSDocument> detached = new ArrayList<>();
            detached.add(new InMemoryDocument(f, name));
            v.setDetachedContents(detached);
        }

        Reports reports = v.validateDocument();
        SimpleReport sr = reports.getSimpleReport();
        String sigId = sr.getFirstSignatureId();
        resp.put("ok", true);
        resp.put("signatureId", sigId);
        Indication ind = sigId == null ? null : sr.getIndication(sigId);
        SubIndication sub = sigId == null ? null : sr.getSubIndication(sigId);
        resp.put("indication", ind == null ? null : ind.name());
        resp.put("subIndication", sub == null ? null : sub.name());
    }

    // ---- helpers ----

    private static X509Certificate parseCert(String b64) throws Exception {
        byte[] der = Base64.getDecoder().decode(b64);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    private static String text(JsonNode n, String field, String dflt) {
        JsonNode f = n.get(field);
        return (f == null || f.isNull()) ? dflt : f.asText();
    }

    private static String reqText(JsonNode n, String field) {
        JsonNode f = n.get(field);
        if (f == null || f.isNull() || f.asText().isEmpty()) {
            throw new IllegalArgumentException("missing required field: " + field);
        }
        return f.asText();
    }

    private static String describe(Throwable t) {
        StringBuilder sb = new StringBuilder();
        sb.append(t.getClass().getSimpleName());
        if (t.getMessage() != null) {
            sb.append(": ").append(t.getMessage());
        }
        Throwable cause = t.getCause();
        int depth = 0;
        while (cause != null && depth < 4) {
            sb.append(" <- ").append(cause.getClass().getSimpleName());
            if (cause.getMessage() != null) {
                sb.append(": ").append(cause.getMessage());
            }
            cause = cause.getCause();
            depth++;
        }
        return sb.toString();
    }
}
