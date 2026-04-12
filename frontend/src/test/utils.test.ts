/**
 * Frontend Tests — Utility Functions (lib/utils.ts)
 *
 * Tests the cn() className merger used throughout the UI.
 */

import { describe, it, expect } from "vitest";
import { cn } from "@/lib/utils";

describe("cn() — className merger", () => {
  it("returns a single class unchanged", () => {
    expect(cn("text-red-500")).toBe("text-red-500");
  });

  it("merges multiple classes", () => {
    const result = cn("flex", "items-center", "gap-2");
    expect(result).toContain("flex");
    expect(result).toContain("items-center");
    expect(result).toContain("gap-2");
  });

  it("handles Tailwind merge: later class wins on conflict", () => {
    // p-4 and p-8 conflict — the last one should win
    const result = cn("p-4", "p-8");
    expect(result).toBe("p-8");
    expect(result).not.toContain("p-4");
  });

  it("handles conditional classes with falsy values", () => {
    const result = cn("base", false && "conditional", undefined, null, "final");
    expect(result).toContain("base");
    expect(result).toContain("final");
    expect(result).not.toContain("conditional");
    expect(result).not.toContain("false");
    expect(result).not.toContain("null");
  });

  it("handles object syntax for conditional classes", () => {
    const isActive = true;
    const isDisabled = false;
    const result = cn({ "bg-blue-500": isActive, "opacity-50": isDisabled });
    expect(result).toContain("bg-blue-500");
    expect(result).not.toContain("opacity-50");
  });

  it("handles empty arguments gracefully", () => {
    expect(cn()).toBe("");
    expect(cn("")).toBe("");
  });

  it("merges tailwind border classes correctly", () => {
    const result = cn("border-red-500", "border-blue-700");
    expect(result).toBe("border-blue-700");
  });

  it("does not duplicate identical classes", () => {
    const result = cn("flex", "flex", "items-center");
    const classes = result.split(" ");
    const flexCount = classes.filter((c) => c === "flex").length;
    expect(flexCount).toBe(1);
  });
});
