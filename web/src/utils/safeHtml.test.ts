// Bundle-8 / Audit L-019 / CWE-79:
// the safeHtml.ts placeholder MUST throw if invoked before the real
// DOMPurify-backed implementation is wired. This catches the
// "imported the helper but forgot to add dompurify" regression at test
// time instead of at runtime against unsanitized HTML.

import { describe, it, expect } from 'vitest';
import { sanitizeHtml } from './safeHtml';

describe('safeHtml.sanitizeHtml — Bundle-8 / L-019', () => {
  it('returns empty string for empty input without throwing', () => {
    expect(sanitizeHtml('')).toBe('');
  });

  it('throws a clear error for any non-empty input (placeholder behaviour)', () => {
    expect(() => sanitizeHtml('<b>bold</b>')).toThrow(/safeHtml.sanitizeHtml is a placeholder/);
  });

  it('error message points readers at the activation procedure', () => {
    try {
      sanitizeHtml('<script>x</script>');
      throw new Error('should have thrown');
    } catch (e) {
      expect(String(e)).toMatch(/dompurify/);
      expect(String(e)).toMatch(/safeHtml\.ts file header/);
    }
  });
});
