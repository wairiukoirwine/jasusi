import { describe, expect, it } from "vitest";
import { categoryLabel, niceMax, percent, shortDate } from "./format";

describe("format helpers", () => {
  it("labels known and unknown categories", () => {
    expect(categoryLabel("mpesa_reversal_scam")).toBe("M-Pesa reversal scam");
    expect(categoryLabel("new_kind")).toBe("new kind");
  });
  it("formats dates without time zones shifting the day", () => {
    expect(shortDate("2026-11-16")).toBe("16 Nov");
    expect(shortDate("2026-01-03T23:59:00+00:00")).toBe("3 Jan");
  });
  it("handles a zero total", () => {
    expect(percent(1, 0)).toBe(0);
    expect(percent(1, 3)).toBe(33);
  });
  it("picks round axis maxima", () => {
    expect(niceMax(0)).toBe(4);
    expect(niceMax(7)).toBe(10);
    expect(niceMax(13)).toBe(20);
    expect(niceMax(21)).toBe(40);
    expect(niceMax(41)).toBe(50);
    expect(niceMax(100)).toBe(100);
  });
});
