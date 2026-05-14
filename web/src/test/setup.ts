import '@testing-library/jest-dom';

// Phase 1 (Foundation Primitives) global polyfills
// =================================================
// Headless UI's Combobox + Dialog use ResizeObserver internally to
// track trigger-element movement (focus-management edge cases on
// scroll / resize). jsdom does not implement ResizeObserver — without
// a polyfill, Combobox.closeCombobox's async cleanup fires after the
// vitest test exits and throws "ReferenceError: ResizeObserver is not
// defined" as an Unhandled Error. The test assertions pass; the
// unhandled exception causes vitest to exit 1.
//
// A minimal stub is sufficient. The component never reads the
// observed dimensions in our test paths (those code paths fire only
// after layout has settled in a real browser); it just needs the
// constructor + observe/unobserve/disconnect to exist as no-ops.
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;
}

// Headless UI also touches Element.prototype.scrollIntoView during
// keyboard navigation of Combobox.Options. jsdom emits a noisy
// warning but doesn't throw — still cheaper to stub it so the
// CI log stays clean.
if (typeof Element !== 'undefined' && !Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = function () {};
}
