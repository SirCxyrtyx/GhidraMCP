package com.lauriewired;

import com.lauriewired.ProgramTargets.Window;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import junit.framework.TestCase;

public class ProgramTargetsTest extends TestCase {
    private final ProgramTargets targets = new ProgramTargets();
    private final Program a = program("same.exe", "/one/same.exe", new AtomicBoolean());
    private final Program b = program("same.exe", "/two/same.exe", new AtomicBoolean());
    private final Program c = program("A & B+测试.exe", "/folder/A & B+测试.exe", new AtomicBoolean());
    private final Program[] open = {a, b, c};

    public void testSelectByIdPathAndNameWithoutChangingActive() throws Exception {
        List<?> entries = entries(targets.list(one(open, a), window(open, a)));
        assertEquals(3, entries.size());
        Map<?, ?> second = (Map<?, ?>) entries.get(1);
        String id = (String) second.get("program_id");
        assertSame(b, resolve(open, a, id));
        assertSame(b, resolve(open, c, id));
        assertSame(b, resolve(open, a, "/two/same.exe"));
        assertSame(c, resolve(open, a, "A & B+测试.exe"));
        assertSame(a, resolve(open, a, null));
        assertEquals(Boolean.FALSE, second.get("active"));
        assertTrue(targets.list(one(open, c), window(open, c)).contains(id));
    }

    public void testRejectAmbiguousMissingEmptyAndClosedTargets() throws Exception {
        assertRejected(open, a, "same.exe", "Ambiguous");
        assertRejected(open, a, "missing.exe", "not open");
        assertRejected(open, a, "", "must not be empty");
        assertRejected(new Program[0], null, null, "No program");
        String id = (String) ((Map<?, ?>) entries(targets.list(one(open, a), window(open, a)))
            .get(1)).get("program_id");
        assertRejected(new Program[] {a, c}, a, id, "not open");
        AtomicBoolean closed = new AtomicBoolean(true);
        Program gone = program("gone.exe", "/gone.exe", closed);
        assertRejected(new Program[] {a, gone}, a, "gone.exe", "not open");
    }

    public void testSamePathsFromDifferentProjectsRequireId() {
        Program other = program("same.exe", "/one/same.exe", new AtomicBoolean());
        assertRejected(new Program[] {a, other}, a, "/one/same.exe", "Ambiguous");
    }

    public void testProgramsInEveryWindowAreListedOnce() throws Exception {
        Window<String> first = new Window<>("t1", "CodeBrowser", new Program[] {a, b}, a);
        Window<String> second = new Window<>("t2", "CodeBrowser(2)", new Program[] {c}, c);
        Window<String> third = new Window<>("t3", "CodeBrowser(3)", new Program[] {b}, b);
        List<Window<String>> windows = Arrays.asList(first, second, third);

        List<?> entries = entries(targets.list(windows, second));
        assertEquals(3, entries.size());
        assertEquals(Arrays.asList("CodeBrowser", "CodeBrowser(3)"),
            ((Map<?, ?>) entries.get(1)).get("windows"));
        assertEquals(Collections.singletonList("CodeBrowser(2)"),
            ((Map<?, ?>) entries.get(2)).get("windows"));
        assertEquals(Boolean.TRUE, ((Map<?, ?>) entries.get(2)).get("active"));
        assertEquals(Boolean.FALSE, ((Map<?, ?>) entries.get(0)).get("active"));

        // A program only open in a later window is reachable.
        assertSame(c, targets.resolve(windows, first, "/folder/A & B+测试.exe").program);
        // The default target follows the focused window.
        assertSame(second, targets.resolve(windows, second, null).window);
        assertSame(a, targets.resolve(windows, first, null).program);
    }

    public void testOwnerPrefersAWindowShowingTheProgram() {
        Window<String> first = new Window<>("t1", "CodeBrowser", new Program[] {a, b}, a);
        Window<String> third = new Window<>("t3", "CodeBrowser(3)", new Program[] {b}, b);
        List<Window<String>> windows = Arrays.asList(first, third);

        // b is a background tab in the focused window but current in another.
        assertSame(third, targets.resolve(windows, first, "/two/same.exe").window);
        // Once the focused window shows it, that window wins.
        Window<String> showing = new Window<>("t1", "CodeBrowser", new Program[] {a, b}, b);
        assertSame(showing, targets.owner(Arrays.asList(showing, third), showing, b));
        // Held only as a background tab: still resolvable, owned by the holder.
        Window<String> background = new Window<>("t4", "CodeBrowser(4)", new Program[] {c, a}, a);
        assertSame(background, targets.owner(Arrays.asList(first, background), first, c));
    }

    private Program resolve(Program[] programs, Program active, String selector) {
        return targets.resolve(one(programs, active), window(programs, active), selector).program;
    }

    private void assertRejected(Program[] programs, Program active, String selector, String message) {
        try {
            resolve(programs, active, selector);
            fail("Expected target rejection");
        }
        catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(message));
        }
    }

    private static List<?> entries(String listing) throws Exception {
        return (List<?>) ((Map<?, ?>) Json.parse(listing)).get("programs");
    }

    private static Window<String> window(Program[] programs, Program current) {
        return new Window<>("tool", "CodeBrowser", programs, current);
    }

    private static List<Window<String>> one(Program[] programs, Program current) {
        return Collections.singletonList(window(programs, current));
    }

    private static Program program(String name, String path, AtomicBoolean closed) {
        DomainFile file = (DomainFile) Proxy.newProxyInstance(DomainFile.class.getClassLoader(),
            new Class<?>[] {DomainFile.class}, (proxy, method, args) -> {
                if (method.getName().equals("getPathname")) return path;
                throw new UnsupportedOperationException(method.getName());
            });
        return (Program) Proxy.newProxyInstance(Program.class.getClassLoader(),
            new Class<?>[] {Program.class}, (proxy, method, args) -> {
                switch (method.getName()) {
                    case "getName": return name;
                    case "getDomainFile": return file;
                    case "getExecutablePath": return "C:/bin/" + name;
                    case "isClosed": return closed.get();
                    default: throw new UnsupportedOperationException(method.getName());
                }
            });
    }
}
