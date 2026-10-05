package io.fluenthealth.gravitee.policy.webhooksignature;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.fluenthealth.gravitee.policy.webhooksignature.configuration.WebhookSignaturePolicyConfiguration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Keeps the console schema and the Java configuration saying the same thing. */
class SchemaTest {

    private static final JsonNode SCHEMA = load();

    @Test
    void declaresNoDefaults() {
        var found = new ArrayList<String>();
        collectDefaults(SCHEMA, "$", found);
        assertThat(found).isEmpty();
    }

    @Test
    void requiresEverythingThatApplies() {
        assertThat(strings(SCHEMA.get("required"))).containsExactlyInAnyOrder("source", "algorithm", "encoding", "secret");
        assertThat(SCHEMA.at("/allOf/0/if/properties/source/const").asText()).isEqualTo("header");
        assertThat(strings(SCHEMA.at("/allOf/0/then/required"))).containsExactlyInAnyOrder("header", "prefix");
        assertThat(strings(SCHEMA.at("/allOf/1/if/properties/source/enum"))).containsExactlyInAnyOrder("mailgun-json", "mailgun-multipart");
        assertThat(strings(SCHEMA.at("/allOf/1/then/required"))).containsExactlyInAnyOrder("maxAgeSeconds", "replayCache");
    }

    @Test
    void enumsMatchTheConfiguration() {
        assertThat(Set.copyOf(strings(SCHEMA.at("/properties/source/enum")))).isEqualTo(WebhookSignaturePolicyConfiguration.SOURCES);
        assertThat(Set.copyOf(strings(SCHEMA.at("/properties/algorithm/enum")))).isEqualTo(WebhookSignaturePolicyConfiguration.ALGORITHMS);
        assertThat(Set.copyOf(strings(SCHEMA.at("/properties/encoding/enum")))).isEqualTo(WebhookSignaturePolicyConfiguration.ENCODINGS);
    }

    @Test
    void everyPropertyHasAConfigurationField() {
        var fields = new HashSet<String>();
        for (var field : WebhookSignaturePolicyConfiguration.class.getDeclaredFields()) {
            if (!java.lang.reflect.Modifier.isStatic(field.getModifiers())) {
                fields.add(field.getName());
            }
        }
        var properties = new HashSet<String>();
        SCHEMA.get("properties").fieldNames().forEachRemaining(properties::add);
        assertThat(properties).isEqualTo(fields);
    }

    private static void collectDefaults(JsonNode node, String path, List<String> found) {
        if (node.isObject()) {
            node.fieldNames().forEachRemaining(name -> {
                if (name.equals("default")) {
                    found.add(path + "/default");
                }
                collectDefaults(node.get(name), path + "/" + name, found);
            });
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                collectDefaults(node.get(i), path + "[" + i + "]", found);
            }
        }
    }

    private static List<String> strings(JsonNode array) {
        var values = new ArrayList<String>();
        array.forEach(v -> values.add(v.asText()));
        return values;
    }

    private static JsonNode load() {
        try (var in = SchemaTest.class.getResourceAsStream("/gravitee.json")) {
            return new ObjectMapper().readTree(in);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
