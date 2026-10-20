package com.lauriewired;

import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Registry for the programs open across every tool window in this Ghidra process. A program open
 * in several windows is one target. Access only on the Swing event thread.
 */
final class ProgramTargets {
    private final Map<Program, String> ids = new IdentityHashMap<>();

    /** One tool window's open programs, captured on the Swing event thread. */
    static final class Window<T> {
        final T tool;
        final String name;
        final Program[] programs;
        final Program current;

        Window(T tool, String name, Program[] programs, Program current) {
            this.tool = tool;
            this.name = name;
            this.programs = programs;
            this.current = current;
        }

        boolean holds(Program program) {
            for (Program open : programs) {
                if (open == program) return true;
            }
            return false;
        }
    }

    /** A resolved program and the window whose cursor, services and script state it uses. */
    static final class Target<T> {
        final Program program;
        final Window<T> window;

        Target(Program program, Window<T> window) {
            this.program = program;
            this.window = window;
        }
    }

    String list(List<? extends Window<?>> windows, Window<?> active) {
        List<Program> programs = refresh(windows);
        Program activeProgram = active == null ? null : active.current;
        List<String> entries = new ArrayList<>();
        for (Program program : programs) {
            List<String> holders = new ArrayList<>();
            for (Window<?> window : windows) {
                if (window.holds(program)) holders.add(Json.quote(window.name));
            }
            entries.add(new Json.Obj()
                .str("program_id", ids.get(program))
                .str("name", program.getName())
                .str("path", path(program))
                .str("executable_path", program.getExecutablePath())
                .bool("active", program == activeProgram)
                .raw("windows", Json.array(holders)).done());
        }
        return new Json.Obj().raw("programs", Json.array(entries)).done();
    }

    /**
     * Resolve a program_id, project path or unique name. A null selector means the current program
     * of {@code active}, the most recently focused window.
     */
    <T> Target<T> resolve(List<Window<T>> windows, Window<T> active, String selector) {
        List<Program> programs = refresh(windows);
        if (selector == null) {
            if (active == null || active.current == null || !ids.containsKey(active.current)) {
                throw new IllegalArgumentException("No program loaded");
            }
            return new Target<>(active.current, active);
        }
        if (selector.isEmpty()) {
            throw new IllegalArgumentException("program must not be empty; use list_programs");
        }
        for (Program program : programs) {
            if (selector.equals(ids.get(program))) {
                return new Target<>(program, owner(windows, active, program));
            }
        }
        List<Program> matches = new ArrayList<>();
        for (Program program : programs) {
            if (selector.equals(path(program)) || selector.equals(program.getName())) {
                matches.add(program);
            }
        }
        if (matches.size() == 1) {
            return new Target<>(matches.get(0), owner(windows, active, matches.get(0)));
        }
        if (matches.size() > 1) {
            throw new IllegalArgumentException("Ambiguous program: " + selector +
                ". Use a program_id from list_programs.");
        }
        throw new IllegalArgumentException("Program is not open: " + selector +
            ". Use list_programs to see available targets.");
    }

    /**
     * The window a program's GUI state comes from: one showing it as the current tab, preferring
     * the focused window, otherwise any window that has it open.
     */
    <T> Window<T> owner(List<Window<T>> windows, Window<T> active, Program program) {
        if (active != null && active.current == program) return active;
        for (Window<T> window : windows) {
            if (window.current == program) return window;
        }
        if (active != null && active.holds(program)) return active;
        for (Window<T> window : windows) {
            if (window.holds(program)) return window;
        }
        return null;
    }

    /** Drop closed programs, assign ids to new ones, and return the open programs in order. */
    private List<Program> refresh(List<? extends Window<?>> windows) {
        List<Program> open = new ArrayList<>();
        Map<Program, Boolean> seen = new IdentityHashMap<>();
        for (Window<?> window : windows) {
            for (Program program : window.programs) {
                if (!program.isClosed() && seen.put(program, Boolean.TRUE) == null) {
                    open.add(program);
                }
            }
        }
        ids.keySet().removeIf(p -> !seen.containsKey(p));
        for (Program program : open) {
            ids.computeIfAbsent(program, p -> UUID.randomUUID().toString());
        }
        return open;
    }

    private String path(Program program) {
        return program.getDomainFile() == null ? null : program.getDomainFile().getPathname();
    }
}
