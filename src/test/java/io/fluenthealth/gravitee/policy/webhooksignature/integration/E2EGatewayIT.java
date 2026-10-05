package io.fluenthealth.gravitee.policy.webhooksignature.integration;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.tomakehurst.wiremock.client.WireMock;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.output.OutputFrame;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

/**
 * Runs the packaged plugin inside a real APIM management API and gateway, configures an API through
 * the official Terraform provider, and pushes signed webhooks through it to a WireMock backend.
 *
 * <p>What it proves that the unit tests cannot: the management API accepts the schema; the gateway
 * hands the policy the same raw bytes the sender signed; template expressions in {@code secret}
 * resolve on the real engine; a verified multipart body — binary attachment included — reaches the
 * backend byte for byte; Mailgun freshness and replay checks work against a real cache resource,
 * and are off when configured off; and a flow the management API let through with an incomplete
 * configuration still fails closed.
 */
public class E2EGatewayIT {

    private static final Logger logger = LoggerFactory.getLogger(E2EGatewayIT.class);
    private static final Network network = Network.newNetwork();
    private static final String MONGO_URI = "mongodb://mongodb:27017/gravitee?serverSelectionTimeoutMS=5000&connectTimeoutMS=5000&socketTimeoutMS=5000";

    /** APIM version under test. Defaults to the latest supported release; CI runs the full range. */
    private static final String APIM_VERSION = System.getProperty("apim.version", "4.12.20");

    private static final String GITHUB_SECRET = "gh-webhook-test-secret";
    private static final String GITHUB_SIGNATURE = "sha256=c7021dee67411a38556d99fddb58023f2ec25f8509a664d0bc49fb9a6a23ff35";
    private static final String MAILGUN_KEY = "mailgun-signing-key-test";
    private static final String MAILGUN_CONTENT_TYPE = "multipart/form-data; boundary=----MailgunBoundary7MA4YWxkTrZu0gW";

    private static final MongoDBContainer mongodb = new MongoDBContainer("mongo:7.0").withNetwork(network).withNetworkAliases("mongodb");

    private static final GenericContainer<?> wiremock = new GenericContainer<>("wiremock/wiremock:3.5.4")
        .withNetwork(network)
        .withNetworkAliases("wiremock")
        .withExposedPorts(8080)
        .withLogConsumer(filteredLogConsumer("wiremock"))
        .waitingFor(Wait.forHttp("/__admin").forStatusCode(200));

    private static final GenericContainer<?> managementApi = new GenericContainer<>("graviteeio/apim-management-api:" + APIM_VERSION)
        .withCreateContainerCmdModifier(cmd -> cmd.withUser("root"))
        .withNetwork(network)
        .withNetworkAliases("management")
        .withExposedPorts(8083, 18083)
        .withEnv("gravitee_management_mongodb_uri", MONGO_URI)
        .withEnv("gravitee_analytics_type", "none")
        .withEnv("gravitee_reporters_elasticsearch_enabled", "false")
        .withEnv("gravitee_alerts_enabled", "false")
        .withEnv("gravitee_services_dictionary_enabled", "false")
        .withEnv("gravitee_services_organization_enabled", "false")
        .withEnv("gravitee_services_access_point_enabled", "false")
        .withEnv("gravitee_services_sync_delay", "1000")
        .withEnv("gravitee_services_sync_unit", "MILLISECONDS")
        .withEnv("gravitee_plugins_path_0", "/opt/graviteeio-management-api/plugins")
        .withEnv("gravitee_plugins_path_1", "/opt/graviteeio-management-api/plugins-ext")
        .withEnv("gravitee_services_core_http_enabled", "true")
        .withEnv("gravitee_services_core_http_port", "18083")
        .withEnv("gravitee_services_core_http_host", "0.0.0.0")
        .withEnv("gravitee_services_core_http_authentication_type", "none")
        .withLogConsumer(filteredLogConsumer("mgmt"))
        .dependsOn(mongodb)
        .waitingFor(Wait.forHttp("/_node/health").forPort(18083).forStatusCode(200).withStartupTimeout(Duration.ofSeconds(300)));

    private static final GenericContainer<?> gateway = new GenericContainer<>("graviteeio/apim-gateway:" + APIM_VERSION)
        .withCreateContainerCmdModifier(cmd -> cmd.withUser("root"))
        .withNetwork(network)
        .withNetworkAliases("gateway")
        .withExposedPorts(8082, 18082)
        .withEnv("gravitee_management_mongodb_uri", MONGO_URI)
        .withEnv("gravitee_ratelimit_mongodb_uri", MONGO_URI)
        .withEnv("gravitee_analytics_type", "none")
        .withEnv("gravitee_reporters_elasticsearch_enabled", "false")
        .withEnv("gravitee_plugins_path_0", "/opt/graviteeio-gateway/plugins")
        .withEnv("gravitee_plugins_path_1", "/opt/graviteeio-gateway/plugins-ext")
        .withEnv("gravitee_services_core_http_enabled", "true")
        .withEnv("gravitee_services_core_http_port", "18082")
        .withEnv("gravitee_services_core_http_host", "0.0.0.0")
        .withEnv("gravitee_services_core_http_authentication_type", "none")
        .withEnv("gravitee_services_sync_delay", "1000")
        .withEnv("gravitee_services_sync_unit", "MILLISECONDS")
        .withEnv("gravitee_logging_categories_io.fluenthealth.gravitee.policy.webhooksignature", "DEBUG")
        .withLogConsumer(filteredLogConsumer("gateway"))
        .dependsOn(mongodb, managementApi)
        .waitingFor(Wait.forHttp("/_node/health").forPort(18082).forStatusCode(200).withStartupTimeout(Duration.ofSeconds(300)));

    private static final HttpClient httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private static WireMock wireMockClient;
    private static String gatewayBase;
    private static String mgmtBase;

    @BeforeAll
    static void setup() throws Exception {
        Path pluginZip;
        try (var files = Files.list(Paths.get("target"))) {
            pluginZip = files.filter(p -> p.toString().endsWith(".zip")).findFirst().orElseThrow(() -> new IllegalStateException("Plugin ZIP not found"));
        }

        mongodb.start();
        wiremock.start();
        wireMockClient = new WireMock(wiremock.getHost(), wiremock.getMappedPort(8080));

        managementApi.withCopyFileToContainer(
            MountableFile.forHostPath(pluginZip),
            "/opt/graviteeio-management-api/plugins-ext/" + pluginZip.getFileName()
        );
        managementApi.start();

        gateway.withCopyFileToContainer(MountableFile.forHostPath(pluginZip), "/opt/graviteeio-gateway/plugins-ext/" + pluginZip.getFileName());
        gateway.start();

        mgmtBase = "http://" + managementApi.getHost() + ":" + managementApi.getMappedPort(8083);
        gatewayBase = "http://" + gateway.getHost() + ":" + gateway.getMappedPort(8082) + "/hooks";

        var dir = terraformDir("api");
        Files.writeString(dir.resolve("main.tf"), providerBlock() + API);
        runTerraform(dir, "init");
        runTerraform(dir, "apply", "-auto-approve");

        Awaitility
            .await()
            .atMost(Duration.ofSeconds(60))
            .pollInterval(Duration.ofSeconds(2))
            .until(() -> {
                try {
                    return post("/github", new byte[0], "application/json", null).statusCode() != 404;
                } catch (Exception e) {
                    return false;
                }
            });
    }

    @AfterAll
    static void tearDown() {
        Stream.of(gateway, managementApi, wiremock, mongodb).filter(Objects::nonNull).forEach(GenericContainer::stop);
        network.close();
    }

    @BeforeEach
    void resetBackend() {
        wireMockClient.resetMappings();
        wireMockClient.resetRequests();
        wireMockClient.register(any(urlPathMatching("/backend/.*")).willReturn(aResponse().withStatus(200).withBody("{\"status\":\"ok\"}")));
    }

    @Test
    void githubSignedDeliveryReachesTheBackendWithItsBodyIntact() throws Exception {
        var body = fixture("github-ping.json");

        var response = post("/github", body, "application/json", GITHUB_SIGNATURE);

        assertThat(response.statusCode()).isEqualTo(200);
        wireMockClient.verifyThat(1, postRequestedFor(urlEqualTo("/backend/github")).withRequestBody(binaryEqualTo(body)));
    }

    @Test
    void githubForgedDeliveryIsRejectedBeforeTheBackend() throws Exception {
        var body = fixture("github-ping.json");
        body[body.length - 2] ^= 1;

        var response = post("/github", body, "application/json", GITHUB_SIGNATURE);

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(new String(response.body())).contains("Invalid signature");
        wireMockClient.verifyThat(0, anyRequestedFor(urlPathMatching("/backend/.*")));
    }

    @Test
    void githubMalformedHeaderIs401Not500() throws Exception {
        var response = post("/github", fixture("github-ping.json"), "application/json", "garbage");

        assertThat(response.statusCode()).isEqualTo(401);
        wireMockClient.verifyThat(0, anyRequestedFor(urlPathMatching("/backend/.*")));
    }

    @Test
    void mailgunRouteForwardsItsBinaryAttachmentByteForByte() throws Exception {
        var body = fixture("mailgun-route.multipart");

        var response = post("/mailgun-route", body, MAILGUN_CONTENT_TYPE, null);

        assertThat(response.statusCode()).isEqualTo(200);
        wireMockClient.verifyThat(1, postRequestedFor(urlEqualTo("/backend/mailgun-route")).withRequestBody(binaryEqualTo(body)));
    }

    @Test
    void mailgunRouteWithoutSignatureFieldsIs400() throws Exception {
        var body = new String(fixture("mailgun-route.multipart"), java.nio.charset.StandardCharsets.ISO_8859_1)
            .replace("name=\"signature\"", "name=\"x\"")
            .getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);

        var response = post("/mailgun-route", body, MAILGUN_CONTENT_TYPE, null);

        assertThat(response.statusCode()).isEqualTo(400);
        wireMockClient.verifyThat(0, anyRequestedFor(urlPathMatching("/backend/.*")));
    }

    @Test
    void mailgunRouteWithFreshnessAndReplayOffAcceptsAnOldRepeatedDelivery() throws Exception {
        // maxAgeSeconds = 0, replayCache = "": a plain signature check, as before tightening.
        var body = fixture("mailgun-route.multipart");

        assertThat(post("/mailgun-route", body, MAILGUN_CONTENT_TYPE, null).statusCode()).isEqualTo(200);
        assertThat(post("/mailgun-route", body, MAILGUN_CONTENT_TYPE, null).statusCode()).isEqualTo(200);
        wireMockClient.verifyThat(2, postRequestedFor(urlEqualTo("/backend/mailgun-route")));
    }

    @Test
    void mailgunEventFreshDeliveryPassesOnceThenIsRefusedAsAReplay() throws Exception {
        var body = mailgunEvent(Instant.now().getEpochSecond(), UUID.randomUUID().toString().replace("-", ""));

        assertThat(post("/mailgun-event", body, "application/json", null).statusCode()).isEqualTo(200);
        var replay = post("/mailgun-event", body, "application/json", null);

        assertThat(replay.statusCode()).isEqualTo(401);
        assertThat(new String(replay.body())).contains("already been used");
        wireMockClient.verifyThat(1, postRequestedFor(urlEqualTo("/backend/mailgun-event")).withRequestBody(binaryEqualTo(body)));
    }

    @Test
    void mailgunEventWithAnOldTimestampIsRefusedAsExpired() throws Exception {
        // The fixture is authentically signed, but in 2025.
        var response = post("/mailgun-event", fixture("mailgun-event.json"), "application/json", null);

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(new String(response.body())).contains("expired");
        wireMockClient.verifyThat(0, anyRequestedFor(urlPathMatching("/backend/.*")));
    }

    /** A Mailgun event signed now. Signing here is test scaffolding; the unit tests pin the HMAC to external vectors. */
    private static byte[] mailgunEvent(long timestamp, String token) throws Exception {
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(MAILGUN_KEY.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"));
        var signature = HexFormat.of().formatHex(mac.doFinal((timestamp + token).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        return (
            "{\"signature\":{\"timestamp\":\"" + timestamp + "\",\"token\":\"" + token + "\",\"signature\":\"" + signature + "\"}," +
            "\"event-data\":{\"event\":\"delivered\",\"recipient\":\"alice@example.com\"}}"
        ).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    @Test
    void aMisconfiguredFlowFailsClosedAtRequestTime() throws Exception {
        // The management API accepted this definition: it does not validate policy configuration
        // against gravitee.json. The policy's own per-request check is the guard that holds.
        var response = post("/misconfigured", fixture("github-ping.json"), "application/json", GITHUB_SIGNATURE);

        assertThat(response.statusCode()).isEqualTo(500);
        assertThat(new String(response.body())).contains("misconfigured");
        wireMockClient.verifyThat(0, anyRequestedFor(urlPathMatching("/backend/.*")));
    }

    // ── API definitions ──────────────────────────────────────────────────────

    /**
     * One API, one flow per dialect. The GitHub secret goes through an API property so that the
     * {@code secret} field is exercised as a real template expression, not just a literal.
     */
    private static final String API = """
        resource "apim_apiv4" "webhooks" {
          name            = "Webhook Signature E2E"
          hrid            = "webhook-signature-e2e"
          version         = "1.0.0"
          lifecycle_state = "PUBLISHED"
          type            = "PROXY"
          state           = "STARTED"

          properties = [{ key = "github-webhook-secret", value = "%s" }]

          listeners = [{
            http = {
              type        = "HTTP"
              paths       = [{ path = "/hooks" }]
              entrypoints = [{ type = "http-proxy" }]
            }
          }]

          endpoint_groups = [{
            name = "default-group"
            type = "http-proxy"
            endpoints = [{
              name          = "backend"
              type          = "http-proxy"
              configuration = jsonencode({ target = "http://wiremock:8080/backend" })
            }]
          }]

          flows = [
            {
              name      = "GitHub"
              enabled   = true
              selectors = [{ http = { type = "HTTP", path = "/github", path_operator = "STARTS_WITH" } }]
              request = [{
                policy  = "webhook-signature"
                enabled = true
                configuration = jsonencode({
                  source    = "header"
                  header    = "X-Hub-Signature-256"
                  prefix    = "sha256="
                  algorithm = "HmacSHA256"
                  encoding  = "hex"
                  secret    = "{#api.properties['github-webhook-secret']}"
                })
              }]
            },
            {
              name      = "Mailgun route"
              enabled   = true
              selectors = [{ http = { type = "HTTP", path = "/mailgun-route", path_operator = "STARTS_WITH" } }]
              request = [{
                policy  = "webhook-signature"
                enabled = true
                configuration = jsonencode({
                  source        = "mailgun-multipart"
                  algorithm     = "HmacSHA256"
                  encoding      = "hex"
                  secret        = "%s"
                  maxAgeSeconds = 0
                  replayCache   = ""
                })
              }]
            },
            {
              name      = "Mailgun event"
              enabled   = true
              selectors = [{ http = { type = "HTTP", path = "/mailgun-event", path_operator = "STARTS_WITH" } }]
              request = [{
                policy  = "webhook-signature"
                enabled = true
                configuration = jsonencode({
                  source        = "mailgun-json"
                  algorithm     = "HmacSHA256"
                  encoding      = "hex"
                  secret        = "%s"
                  maxAgeSeconds = 300
                  replayCache   = "replay-cache"
                })
              }]
            },
            {
              name      = "Misconfigured"
              enabled   = true
              selectors = [{ http = { type = "HTTP", path = "/misconfigured", path_operator = "STARTS_WITH" } }]
              request = [{
                policy  = "webhook-signature"
                enabled = true
                configuration = jsonencode({
                  source    = "header"
                  prefix    = "sha256="
                  algorithm = "HmacSHA256"
                  encoding  = "hex"
                  secret    = "%s"
                })
              }]
            },
          ]

          resources = [{
            name    = "replay-cache"
            type    = "cache"
            enabled = true
            configuration = jsonencode({
              timeToIdleSeconds   = 0
              timeToLiveSeconds   = 600
              maxEntriesLocalHeap = 1000
            })
          }]

          plans = [{
            name     = "Keyless"
            hrid     = "keyless"
            mode     = "STANDARD"
            security = { type = "KEY_LESS" }
            status   = "PUBLISHED"
          }]
        }
        """.formatted(GITHUB_SECRET, MAILGUN_KEY, MAILGUN_KEY, GITHUB_SECRET);


    private static String providerBlock() {
        return """
            terraform {
              required_providers {
                apim = {
                  source  = "gravitee-io/apim"
                  version = "~> 0.5.0"
                }
              }
            }

            provider "apim" {
              server_url = "%s/automation"
              username   = "admin"
              password   = "admin"
            }

            """.formatted(mgmtBase);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static HttpResponse<byte[]> post(String path, byte[] body, String contentType, String signature) throws Exception {
        var builder = HttpRequest
            .newBuilder()
            .uri(URI.create(gatewayBase + path))
            .header("Content-Type", contentType)
            .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        if (signature != null) {
            builder.header("X-Hub-Signature-256", signature);
        }
        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream in = E2EGatewayIT.class.getResourceAsStream("/fixtures/" + name)) {
            return Objects.requireNonNull(in, name).readAllBytes();
        }
    }

    private static Path terraformDir(String name) throws IOException {
        var dir = Files.createDirectories(Paths.get("target/terraform-it", name));
        Files.writeString(dir.resolve(".tool-versions"), "terraform 1.15.1\n");
        return dir;
    }

    private static void runTerraform(Path dir, String... args) throws IOException, InterruptedException {
        if (terraform(dir, args) != 0) {
            throw new RuntimeException("Terraform " + args[0] + " failed (see " + dir.resolve("terraform-" + args[0] + ".log") + ")");
        }
    }

    private static int terraform(Path dir, String... args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add("terraform");
        command.addAll(List.of(args));
        var out = dir.resolve("terraform-" + args[0] + ".log").toFile();
        return new ProcessBuilder(command).directory(dir.toFile()).redirectOutput(out).redirectError(out).start().waitFor();
    }

    /**
     * Forwards container stdout selectively: ERROR lines, anything from this plugin's package, bare
     * throwable headers, and API deploy markers. Everything else is boot noise.
     */
    private static final java.util.regex.Pattern LEADING_TIMESTAMP = java.util.regex.Pattern.compile(
        "^\\d{2}:\\d{2}:\\d{2}\\.\\d{3}\\s+\\[[^\\]]+\\]\\s*"
    );

    private static final java.util.regex.Pattern THROWABLE_HEADER = java.util.regex.Pattern.compile(
        "^(Caused by: )?(java|javax|jakarta|io|com|org)\\.[\\w.$]*(Exception|Error|Throwable)\\b"
    );

    private static final List<String> SILENCED_BOOT_ERRORS = List.of("KubernetesConfig", "EmailNotifierServiceImpl");

    private static Consumer<OutputFrame> filteredLogConsumer(String prefix) {
        return frame -> {
            var line = frame.getUtf8StringWithoutLineEnding();
            if (line.isEmpty()) {
                return;
            }
            var trimmed = LEADING_TIMESTAMP.matcher(line).replaceFirst("");
            if (line.contains(" ERROR ")) {
                if (SILENCED_BOOT_ERRORS.stream().anyMatch(line::contains)) {
                    return;
                }
                logger.error("[{}] {}", prefix, trimmed);
            } else if (line.contains("WebhookSignaturePolicy") || line.contains("io.fluenthealth")) {
                logger.info("[{}] {}", prefix, trimmed);
            } else if (THROWABLE_HEADER.matcher(trimmed).find()) {
                logger.warn("[{}] {}", prefix, trimmed);
            } else if (line.contains("ApiManagerImpl") && (line.contains("has been deployed") || line.contains("has been undeployed"))) {
                logger.info("[{}] {}", prefix, trimmed);
            }
        };
    }
}
