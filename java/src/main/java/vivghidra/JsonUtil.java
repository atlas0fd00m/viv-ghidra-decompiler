package vivghidra;

/**
 * Minimal zero-dependency JSON utilities.
 *
 * Handles parsing and serializing JSON for the JSON-RPC protocol.
 * No external libraries — just Java stdlib.
 *
 * This is intentionally minimal: it handles Maps, Lists, Strings, Numbers,
 * Booleans, and null. It does NOT handle arbitrary Java objects — callers
 * must convert to Maps/Lists first.
 */
import java.util.*;

public class JsonUtil {

    // ─── Parsing ───

    private static class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
            this.pos = 0;
        }

        Object parseValue() {
            skipWhitespace();
            if (pos >= s.length()) throw new RuntimeException("Unexpected end of input");
            char c = s.charAt(pos);
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '"') return parseString();
            if (c == 't' || c == 'f') return parseBoolean();
            if (c == 'n') return parseNull();
            return parseNumber();
        }

        Map<String, Object> parseObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            expect('{');
            skipWhitespace();
            if (peek() == '}') { pos++; return map; }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                Object value = parseValue();
                map.put(key, value);
                skipWhitespace();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == '}') { pos++; break; }
                throw new RuntimeException("Expected ',' or '}' at pos " + pos);
            }
            return map;
        }

        List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            expect('[');
            skipWhitespace();
            if (peek() == ']') { pos++; return list; }
            while (true) {
                Object value = parseValue();
                list.add(value);
                skipWhitespace();
                char c = peek();
                if (c == ',') { pos++; continue; }
                if (c == ']') { pos++; break; }
                throw new RuntimeException("Expected ',' or ']' at pos " + pos);
            }
            return list;
        }

        String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < s.length()) {
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (pos >= s.length()) throw new RuntimeException("Unterminated escape");
                    char esc = s.charAt(pos++);
                    switch (esc) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'n': sb.append('\n'); break;
                        case 't': sb.append('\t'); break;
                        case 'r': sb.append('\r'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'u':
                            if (pos + 4 > s.length()) throw new RuntimeException("Bad unicode escape");
                            String hex = s.substring(pos, pos + 4);
                            sb.append((char) Integer.parseInt(hex, 16));
                            pos += 4;
                            break;
                        default: throw new RuntimeException("Bad escape: \\" + esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new RuntimeException("Unterminated string");
        }

        Object parseNumber() {
            int start = pos;
            if (peek() == '-') pos++;
            while (pos < s.length() && (Character.isDigit(s.charAt(pos)) ||
                    s.charAt(pos) == '.' || s.charAt(pos) == 'e' || s.charAt(pos) == 'E' ||
                    s.charAt(pos) == '+' || s.charAt(pos) == '-')) {
                pos++;
            }
            String num = s.substring(start, pos);
            if (num.contains(".") || num.contains("e") || num.contains("E")) {
                return Double.parseDouble(num);
            }
            long l = Long.parseLong(num);
            if (l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) return (int) l;
            return l;
        }

        Boolean parseBoolean() {
            if (s.startsWith("true", pos)) { pos += 4; return true; }
            if (s.startsWith("false", pos)) { pos += 5; return false; }
            throw new RuntimeException("Expected boolean at pos " + pos);
        }

        Object parseNull() {
            if (s.startsWith("null", pos)) { pos += 4; return null; }
            throw new RuntimeException("Expected null at pos " + pos);
        }

        void skipWhitespace() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++;
        }

        char peek() {
            if (pos >= s.length()) throw new RuntimeException("Unexpected end of input");
            return s.charAt(pos);
        }

        void expect(char c) {
            if (pos >= s.length() || s.charAt(pos) != c)
                throw new RuntimeException("Expected '" + c + "' at pos " + pos);
            pos++;
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parse(String json) {
        Parser p = new Parser(json);
        Object result = p.parseValue();
        if (!(result instanceof Map)) throw new RuntimeException("JSON root must be object");
        return (Map<String, Object>) result;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> parseArray(String json) {
        Parser p = new Parser(json);
        Object result = p.parseValue();
        if (!(result instanceof List)) throw new RuntimeException("JSON root must be array");
        return (List<Object>) result;
    }

    // ─── Serialization ───

    public static String stringify(Object obj) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, obj);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void writeValue(StringBuilder sb, Object obj) {
        if (obj == null) { sb.append("null"); return; }
        if (obj instanceof String) { writeString(sb, (String) obj); return; }
        if (obj instanceof Boolean) { sb.append(obj); return; }
        if (obj instanceof Number) {
            if (obj instanceof Double || obj instanceof Float) {
                double d = ((Number) obj).doubleValue();
                if (d == Math.floor(d) && !Double.isInfinite(d)) {
                    sb.append((long) d);
                } else {
                    sb.append(d);
                }
            } else {
                sb.append(obj);
            }
            return;
        }
        if (obj instanceof Map) { writeObject(sb, (Map<String, Object>) obj); return; }
        if (obj instanceof List) { writeArray(sb, (List<Object>) obj); return; }
        // Fallback: string representation
        writeString(sb, obj.toString());
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\t': sb.append("\\t"); break;
                case '\r': sb.append("\\r"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    private static void writeObject(StringBuilder sb, Map<String, Object> map) {
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, Object> e : map.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            writeString(sb, e.getKey());
            sb.append(':');
            writeValue(sb, e.getValue());
        }
        sb.append('}');
    }

    private static void writeArray(StringBuilder sb, List<Object> list) {
        sb.append('[');
        boolean first = true;
        for (Object item : list) {
            if (!first) sb.append(',');
            first = false;
            writeValue(sb, item);
        }
        sb.append(']');
    }

    // ─── Helpers ───

    public static String getString(Map<String, Object> map, String key, String def) {
        Object v = map.get(key);
        return v != null ? v.toString() : def;
    }

    public static int getInt(Map<String, Object> map, String key, int def) {
        Object v = map.get(key);
        if (v instanceof Number) return ((Number) v).intValue();
        if (v instanceof String) {
            try { return Integer.parseInt((String) v, 16); } catch (Exception e) { return def; }
        }
        return def;
    }

    public static long getLong(Map<String, Object> map, String key, long def) {
        Object v = map.get(key);
        if (v instanceof Number) return ((Number) v).longValue();
        if (v instanceof String) {
            try {
                String s = (String) v;
                if (s.startsWith("0x")) return Long.parseLong(s.substring(2), 16);
                return Long.parseLong(s);
            } catch (Exception e) { return def; }
        }
        return def;
    }

    public static boolean getBool(Map<String, Object> map, String key, boolean def) {
        Object v = map.get(key);
        if (v instanceof Boolean) return (Boolean) v;
        return def;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> getList(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof List) return (List<Object>) v;
        return new ArrayList<>();
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> getMap(Map<String, Object> map, String key) {
        Object v = map.get(key);
        if (v instanceof Map) return (Map<String, Object>) v;
        return new LinkedHashMap<>();
    }
}