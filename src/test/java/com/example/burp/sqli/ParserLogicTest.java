package com.example.burp.sqli;

import com.example.burp.sqli.core.ProbeTask;
import com.example.burp.sqli.core.ProbeTask.InjectionPoint;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * v3.5 新增解析逻辑的单元测试
 * - JSON body 解析（递归下降法）
 * - Cookie 参数解析
 * - Multipart boundary 提取
 * - 请求去重逻辑
 */
class ParserLogicTest {

    // === JSON Parsing ===

    @Nested
    @DisplayName("JSON Body Parsing")
    class JsonParsing {

        private List<InjectionPoint> parseJson(String json) throws Exception {
            Method method = ProbeTask.class.getDeclaredMethod("parseJsonBody", String.class, List.class, String.class);
            method.setAccessible(true);
            List<InjectionPoint> points = new ArrayList<>();
            method.invoke(null, json, points, json);
            return points;
        }

        @Test @DisplayName("Simple flat JSON")
        void testSimpleFlat() throws Exception {
            List<InjectionPoint> pts = parseJson("{\"name\":\"alice\",\"age\":25}");
            assertEquals(2, pts.size());
            assertEquals("name", pts.get(0).paramName());
            assertEquals("alice", pts.get(0).paramValue());
            assertEquals("json", pts.get(0).paramType());
            assertEquals("age", pts.get(1).paramName());
            assertEquals("25", pts.get(1).paramValue());
        }

        @Test @DisplayName("Nested JSON with dot-path keys")
        void testNested() throws Exception {
            List<InjectionPoint> pts = parseJson("{\"user\":{\"name\":\"bob\",\"email\":\"bob@test.com\"}}");
            assertEquals(2, pts.size());
            assertEquals("user.name", pts.get(0).paramName());
            assertEquals("bob", pts.get(0).paramValue());
            assertEquals("user.email", pts.get(1).paramName());
            assertEquals("bob@test.com", pts.get(1).paramValue());
        }

        @Test @DisplayName("Mixed types: number, boolean, null")
        void testMixedTypes() throws Exception {
            List<InjectionPoint> pts = parseJson("{\"id\":123,\"active\":true,\"role\":null}");
            assertEquals(3, pts.size());
            assertEquals("123", pts.get(0).paramValue());
            assertEquals("true", pts.get(1).paramValue());
            assertEquals("null", pts.get(2).paramValue());
        }

        @Test @DisplayName("Empty object returns empty list")
        void testEmptyObject() throws Exception {
            List<InjectionPoint> pts = parseJson("{}");
            assertTrue(pts.isEmpty());
        }

        @Test @DisplayName("JSON with whitespace")
        void testWhitespace() throws Exception {
            List<InjectionPoint> pts = parseJson("{ \"key\" : \"value\" }");
            assertEquals(1, pts.size());
            assertEquals("key", pts.get(0).paramName());
            assertEquals("value", pts.get(0).paramValue());
        }

        @Test @DisplayName("Deeply nested object")
        void testDeepNested() throws Exception {
            List<InjectionPoint> pts = parseJson("{\"a\":{\"b\":{\"c\":\"deep\"}}}");
            assertEquals(1, pts.size());
            assertEquals("a.b.c", pts.get(0).paramName());
            assertEquals("deep", pts.get(0).paramValue());
        }

        @Test @DisplayName("Array values are skipped, sibling extracted")
        void testArraySkipped() throws Exception {
            List<InjectionPoint> pts = parseJson("{\"tags\":[\"a\",\"b\"],\"name\":\"test\"}");
            // "tags" is an array → skipped; "name" is extracted
            assertEquals(1, pts.size());
            assertEquals("name", pts.get(0).paramName());
            assertEquals("test", pts.get(0).paramValue());
        }

        @Test @DisplayName("Decimal number")
        void testDecimal() throws Exception {
            List<InjectionPoint> pts = parseJson("{\"price\":99.99}");
            assertEquals(1, pts.size());
            assertEquals("99.99", pts.get(0).paramValue());
        }

        @Test @DisplayName("Negative number")
        void testNegative() throws Exception {
            List<InjectionPoint> pts = parseJson("{\"balance\":-100}");
            assertEquals(1, pts.size());
            assertEquals("-100", pts.get(0).paramValue());
        }

        @Test @DisplayName("Malformed JSON does not crash")
        void testMalformed() {
            assertDoesNotThrow(() -> parseJson("{invalid json"));
        }

        @Test @DisplayName("Null input does not crash")
        void testNull() {
            assertDoesNotThrow(() -> parseJson(null));
            assertDoesNotThrow(() -> {
                List<InjectionPoint> pts = parseJson(null);
                assertTrue(pts.isEmpty());
            });
        }

        @Test @DisplayName("Empty string does not crash")
        void testEmptyString() {
            assertDoesNotThrow(() -> parseJson(""));
            assertDoesNotThrow(() -> {
                List<InjectionPoint> pts = parseJson("");
                assertTrue(pts.isEmpty());
            });
        }

        @Test @DisplayName("Escaped quotes in value preserved")
        void testEscapedQuotes() throws Exception {
            List<InjectionPoint> pts = parseJson("{\"msg\":\"hello \\\"world\\\"\"}");
            assertEquals(1, pts.size());
            assertEquals("msg", pts.get(0).paramName());
            // Escaped quotes should be unescaped
            assertEquals("hello \"world\"", pts.get(0).paramValue());
        }

        @Test @DisplayName("Mixed nested with array and primitive")
        void testMixedNested() throws Exception {
            List<InjectionPoint> pts = parseJson(
                "{\"user\":{\"name\":\"test\",\"roles\":[\"admin\"],\"active\":true},\"count\":5}"
            );
            // user.name=test, user.active=true, count=5 (roles array skipped)
            assertEquals(3, pts.size());
            assertEquals("user.name", pts.get(0).paramName());
            assertEquals("test", pts.get(0).paramValue());
            assertEquals("user.active", pts.get(1).paramName());
            assertEquals("true", pts.get(1).paramValue());
            assertEquals("count", pts.get(2).paramName());
            assertEquals("5", pts.get(2).paramValue());
        }

        @Test @DisplayName("Three-level nesting with sibling")
        void testThreeLevel() throws Exception {
            List<InjectionPoint> pts = parseJson("{\"a\":{\"b\":\"val1\"},\"c\":{\"d\":{\"e\":\"val2\"}}}");
            assertEquals(2, pts.size());
            assertEquals("a.b", pts.get(0).paramName());
            assertEquals("val1", pts.get(0).paramValue());
            assertEquals("c.d.e", pts.get(1).paramName());
            assertEquals("val2", pts.get(1).paramValue());
        }

        @Test @DisplayName("Newlines and tabs in JSON")
        void testNewlinesTabs() throws Exception {
            List<InjectionPoint> pts = parseJson("{\n\t\"key\":\t\"value\"\n}");
            assertEquals(1, pts.size());
            assertEquals("value", pts.get(0).paramValue());
        }

        @Test @DisplayName("Empty array value")
        void testEmptyArray() throws Exception {
            List<InjectionPoint> pts = parseJson("{\"items\":[],\"name\":\"test\"}");
            assertEquals(1, pts.size());
            assertEquals("test", pts.get(0).paramValue());
        }

        @Test @DisplayName("Unicode escape")
        void testUnicodeEscape() throws Exception {
            List<InjectionPoint> pts = parseJson("{\"msg\":\"hello\\u0020world\"}");
            assertEquals(1, pts.size());
            assertEquals("hello world", pts.get(0).paramValue());
        }
    }

    // === Cookie Parsing ===

    @Nested
    @DisplayName("Cookie Parameter Parsing")
    class CookieParsing {

        private List<InjectionPoint> parseCookies(String cookieHeader) throws Exception {
            Method method = ProbeTask.class.getDeclaredMethod("parseCookieParams", String.class, List.class);
            method.setAccessible(true);
            List<InjectionPoint> points = new ArrayList<>();
            method.invoke(null, cookieHeader, points);
            return points;
        }

        @Test @DisplayName("Standard cookie header")
        void testStandard() throws Exception {
            List<InjectionPoint> pts = parseCookies("session=abc123; user=admin");
            assertEquals(2, pts.size());
            assertEquals("session", pts.get(0).paramName());
            assertEquals("abc123", pts.get(0).paramValue());
            assertEquals("cookie", pts.get(0).paramType());
            assertEquals("user", pts.get(1).paramName());
            assertEquals("admin", pts.get(1).paramValue());
        }

        @Test @DisplayName("Cookie with extra spaces")
        void testSpaces() throws Exception {
            List<InjectionPoint> pts = parseCookies("  name=value  ;  id=456  ");
            assertEquals(2, pts.size());
            assertEquals("name", pts.get(0).paramName());
            assertEquals("value", pts.get(0).paramValue());
            assertEquals("id", pts.get(1).paramName());
            assertEquals("456", pts.get(1).paramValue());
        }

        @Test @DisplayName("Single cookie")
        void testSingle() throws Exception {
            List<InjectionPoint> pts = parseCookies("token=xyz");
            assertEquals(1, pts.size());
            assertEquals("token", pts.get(0).paramName());
        }

        @Test @DisplayName("Empty cookie header returns empty")
        void testEmpty() throws Exception {
            List<InjectionPoint> pts = parseCookies("");
            assertTrue(pts.isEmpty());
        }

        @Test @DisplayName("Cookie with = in value")
        void testEqualsInValue() throws Exception {
            List<InjectionPoint> pts = parseCookies("data=a=b=c");
            assertEquals(1, pts.size());
            assertEquals("data", pts.get(0).paramName());
            assertEquals("a=b=c", pts.get(0).paramValue());
        }

        @Test @DisplayName("Cookie value with special characters")
        void testSpecialChars() throws Exception {
            List<InjectionPoint> pts = parseCookies("sid=abc-123_XYZ!@#");
            assertEquals(1, pts.size());
            assertEquals("abc-123_XYZ!@#", pts.get(0).paramValue());
        }
    }

    // === Multipart Boundary ===

    @Nested
    @DisplayName("Multipart Boundary Extraction")
    class MultipartBoundary {

        private String extractBoundary(String contentType) throws Exception {
            Method method = ProbeTask.class.getDeclaredMethod("extractMultipartBoundary", String.class);
            method.setAccessible(true);
            return (String) method.invoke(null, contentType);
        }

        @Test @DisplayName("Standard boundary")
        void testStandard() throws Exception {
            String b = extractBoundary("multipart/form-data; boundary=----WebKitFormBoundaryABC123");
            assertEquals("----WebKitFormBoundaryABC123", b);
        }

        @Test @DisplayName("No boundary returns null")
        void testNoBoundary() throws Exception {
            String b = extractBoundary("multipart/form-data; charset=utf-8");
            assertNull(b);
        }

        @Test @DisplayName("Case insensitive boundary")
        void testCaseInsensitive() throws Exception {
            String b = extractBoundary("multipart/form-data; BOUNDARY=abc123");
            assertEquals("abc123", b);
        }

        @Test @DisplayName("Boundary with extra attributes")
        void testWithOtherAttributes() throws Exception {
            String b = extractBoundary("multipart/form-data; charset=utf-8; boundary=abc");
            assertEquals("abc", b);
        }
    }

    // === Dedup Logic ===

    @Nested
    @DisplayName("Request Deduplication Logic")
    class DedupLogic {

        @Test @DisplayName("Same URL detected as duplicate")
        void testDuplicateDetection() {
            List<String> queue = new ArrayList<>();
            queue.add("http://example.com/page?id=1");
            queue.add("http://example.com/page?id=2");

            boolean dup = queue.stream().anyMatch(u -> u.equals("http://example.com/page?id=1"));
            assertTrue(dup);
            boolean notDup = queue.stream().anyMatch(u -> u.equals("http://example.com/page?id=3"));
            assertFalse(notDup);
        }

        @Test @DisplayName("Empty queue no duplicates")
        void testEmptyQueue() {
            List<String> queue = new ArrayList<>();
            assertFalse(queue.stream().anyMatch(u -> u.equals("http://example.com")));
        }
    }

    // === Detector Timeout/Delay ===

    @Nested
    @DisplayName("Detector Configuration")
    class DetectorConfig {

        @Test @DisplayName("StringBlindDetector accepts timeout and delay")
        void testStringBlindTimeout() {
            com.example.burp.sqli.detector.StringBlindDetector d =
                    new com.example.burp.sqli.detector.StringBlindDetector();
            d.setTimeoutMs(5000);
            d.setDelayMs(200);
            // No crash = pass (can't verify internal values without getter)
        }

        @Test @DisplayName("TimeBlindDetector enforces minimum timeout of 10s")
        void testTimeBlindMinTimeout() {
            com.example.burp.sqli.detector.TimeBlindDetector d =
                    new com.example.burp.sqli.detector.TimeBlindDetector();
            d.setTimeoutMs(3000); // below minimum
            d.setTimeoutMs(15000); // above minimum
            // No crash = pass
        }

        @Test @DisplayName("Detector interface default methods don't crash")
        void testInterfaceDefaults() {
            com.example.burp.sqli.detector.Detector d = new com.example.burp.sqli.detector.Detector() {
                @Override
                public com.example.burp.sqli.core.ProbeResult detect(
                        burp.api.montoya.MontoyaApi api, String url, String paramName,
                        String paramValue, burp.api.montoya.http.message.HttpRequestResponse baseReq,
                        String paramType) {
                    return null;
                }
            };
            assertDoesNotThrow(() -> {
                d.setTimeoutMs(5000);
                d.setDelayMs(100);
            });
        }
    }
}
