package vivghidra;

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.*;

/**
 * Unit tests for JsonUtil — the zero-dependency JSON parser/serializer.
 *
 * These tests don't require Ghidra — they only test the JSON parsing
 * and serialization logic.
 */
class JsonUtilTest {

    // ─── Parsing ───

    @Test
    @DisplayName("Parse simple object")
    void testParseSimpleObject() {
        Map<String, Object> result = JsonUtil.parse("{\"name\": \"test\", \"value\": 42}");
        assertEquals("test", result.get("name"));
        assertEquals(42, result.get("value"));
    }

    @Test
    @DisplayName("Parse nested object")
    void testParseNestedObject() {
        Map<String, Object> result = JsonUtil.parse(
            "{\"outer\": {\"inner\": \"hello\", \"num\": 100}}");
        @SuppressWarnings("unchecked")
        Map<String, Object> inner = (Map<String, Object>) result.get("outer");
        assertEquals("hello", inner.get("inner"));
        assertEquals(100, inner.get("num"));
    }

    @Test
    @DisplayName("Parse array")
    void testParseArray() {
        List<Object> result = JsonUtil.parseArray("[1, 2, 3, \"four\", true]");
        assertEquals(5, result.size());
        assertEquals(1, result.get(0));
        assertEquals("four", result.get(3));
        assertEquals(true, result.get(4));
    }

    @Test
    @DisplayName("Parse string with escapes")
    void testParseStringEscapes() {
        Map<String, Object> result = JsonUtil.parse(
            "{\"msg\": \"hello\\nworld\\ttab\\\"quote\"}");
        assertEquals("hello\nworld\ttab\"quote", result.get("msg"));
    }

    @Test
    @DisplayName("Parse boolean and null")
    void testParseBoolNull() {
        Map<String, Object> result = JsonUtil.parse(
            "{\"t\": true, \"f\": false, \"n\": null}");
        assertEquals(true, result.get("t"));
        assertEquals(false, result.get("f"));
        assertNull(result.get("n"));
    }

    @Test
    @DisplayName("Parse negative number")
    void testParseNegativeNumber() {
        Map<String, Object> result = JsonUtil.parse("{\"val\": -42}");
        assertEquals(-42, result.get("val"));
    }

    @Test
    @DisplayName("Parse empty object")
    void testParseEmptyObject() {
        Map<String, Object> result = JsonUtil.parse("{}");
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("Parse object with array value")
    void testParseObjectWithArray() {
        Map<String, Object> result = JsonUtil.parse(
            "{\"items\": [1, 2, 3], \"count\": 3}");
        @SuppressWarnings("unchecked")
        List<Object> items = (List<Object>) result.get("items");
        assertEquals(3, items.size());
        assertEquals(3, result.get("count"));
    }

    @Test
    @DisplayName("Parse with whitespace")
    void testParseWithWhitespace() {
        Map<String, Object> result = JsonUtil.parse(
            "  {  \"key\"  :  \"value\"  }  ");
        assertEquals("value", result.get("key"));
    }

    // ─── Serialization ───

    @Test
    @DisplayName("Stringify simple object")
    void testStringifySimple() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", "test");
        map.put("value", 42);
        String json = JsonUtil.stringify(map);
        // Parse it back
        Map<String, Object> parsed = JsonUtil.parse(json);
        assertEquals("test", parsed.get("name"));
        assertEquals(42, parsed.get("value"));
    }

    @Test
    @DisplayName("Stringify string with special chars")
    void testStringifySpecialChars() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("msg", "hello\nworld\"quote\"");
        String json = JsonUtil.stringify(map);
        Map<String, Object> parsed = JsonUtil.parse(json);
        assertEquals("hello\nworld\"quote\"", parsed.get("msg"));
    }

    @Test
    @DisplayName("Stringify nested object")
    void testStringifyNested() {
        Map<String, Object> outer = new LinkedHashMap<>();
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("key", "val");
        outer.put("nested", inner);
        outer.put("arr", Arrays.asList(1, 2, 3));

        String json = JsonUtil.stringify(outer);
        Map<String, Object> parsed = JsonUtil.parse(json);
        @SuppressWarnings("unchecked")
        Map<String, Object> parsedInner = (Map<String, Object>) parsed.get("nested");
        assertEquals("val", parsedInner.get("key"));
    }

    @Test
    @DisplayName("Stringify null and boolean")
    void testStringifyNullBool() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("n", null);
        map.put("t", true);
        map.put("f", false);
        String json = JsonUtil.stringify(map);
        Map<String, Object> parsed = JsonUtil.parse(json);
        assertNull(parsed.get("n"));
        assertEquals(true, parsed.get("t"));
        assertEquals(false, parsed.get("f"));
    }

    // ─── Helper methods ───

    @Test
    @DisplayName("getString with default")
    void testGetStringDefault() {
        Map<String, Object> map = new LinkedHashMap<>();
        assertEquals("default", JsonUtil.getString(map, "missing", "default"));
        map.put("key", "value");
        assertEquals("value", JsonUtil.getString(map, "key", "default"));
    }

    @Test
    @DisplayName("getInt with default")
    void testGetIntDefault() {
        Map<String, Object> map = new LinkedHashMap<>();
        assertEquals(42, JsonUtil.getInt(map, "missing", 42));
        map.put("num", 100);
        assertEquals(100, JsonUtil.getInt(map, "num", 0));
    }

    @Test
    @DisplayName("getLong with hex string")
    void testGetLongHex() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("addr", "0x401000");
        assertEquals(0x401000L, JsonUtil.getLong(map, "addr", 0));
    }

    @Test
    @DisplayName("getBool with default")
    void testGetBoolDefault() {
        Map<String, Object> map = new LinkedHashMap<>();
        assertFalse(JsonUtil.getBool(map, "missing", false));
        map.put("flag", true);
        assertTrue(JsonUtil.getBool(map, "flag", false));
    }

    @Test
    @DisplayName("getList returns empty for missing key")
    void testGetListMissing() {
        Map<String, Object> map = new LinkedHashMap<>();
        List<Object> list = JsonUtil.getList(map, "missing");
        assertTrue(list.isEmpty());
    }

    @Test
    @DisplayName("getMap returns empty for missing key")
    void testGetMapMissing() {
        Map<String, Object> map = new LinkedHashMap<>();
        Map<String, Object> inner = JsonUtil.getMap(map, "missing");
        assertTrue(inner.isEmpty());
    }

    // ─── Round-trip tests ───

    @Test
    @DisplayName("Round-trip complex JSON")
    void testRoundTripComplex() {
        Map<String, Object> original = new LinkedHashMap<>();
        original.put("method", "decompile_function");
        original.put("id", 1);

        Map<String, Object> params = new LinkedHashMap<>();
        params.put("address", "0x401000");
        params.put("mode", "enriched");
        params.put("symbols", Arrays.asList(
            Map.of("name", "main", "address", "0x401000", "is_function", true),
            Map.of("name", "printf", "address", "0x401200", "is_import", true)
        ));
        original.put("params", params);

        String json = JsonUtil.stringify(original);
        Map<String, Object> parsed = JsonUtil.parse(json);

        assertEquals("decompile_function", parsed.get("method"));
        assertEquals(1, parsed.get("id"));

        @SuppressWarnings("unchecked")
        Map<String, Object> parsedParams = (Map<String, Object>) parsed.get("params");
        assertEquals("0x401000", parsedParams.get("address"));
        assertEquals("enriched", parsedParams.get("mode"));

        @SuppressWarnings("unchecked")
        List<Object> parsedSymbols = (List<Object>) parsedParams.get("symbols");
        assertEquals(2, parsedSymbols.size());
    }

    @Test
    @DisplayName("Parse decompile response")
    void testParseDecompileResponse() {
        String json = "{\"id\": 1, \"result\": {\"success\": true, " +
            "\"c_code\": \"int main() { return 0; }\", \"function_name\": \"main\"}}";

        Map<String, Object> parsed = JsonUtil.parse(json);
        assertEquals(1, parsed.get("id"));
        @SuppressWarnings("unchecked")
        Map<String, Object> result = (Map<String, Object>) parsed.get("result");
        assertEquals(true, result.get("success"));
        assertEquals("int main() { return 0; }", result.get("c_code"));
        assertEquals("main", result.get("function_name"));
    }
}