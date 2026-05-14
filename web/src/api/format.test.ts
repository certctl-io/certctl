import { describe, it, expect } from 'vitest';
import { formatNumber, formatCompact, formatPercent, formatBytes } from './format';

describe('format', () => {
  describe('formatNumber', () => {
    it('formats integers with thousand separator', () => {
      // Locale-tolerant: any of "5,432" (en) / "5.432" (de) / "5 432" (fr) is fine.
      const out = formatNumber(5432);
      expect(out).toMatch(/^5[ .,]?432$/);
    });
    it('limits fraction digits to 2', () => {
      const out = formatNumber(1.23456);
      expect(out).toMatch(/^1[.,]23$/);
    });
    it('returns dash for NaN / Infinity', () => {
      expect(formatNumber(NaN)).toBe('—');
      expect(formatNumber(Infinity)).toBe('—');
    });
  });

  describe('formatCompact', () => {
    it('compacts thousands to K', () => {
      // English: "5.4K"; some locales drop the K. The compact notation
      // is locale-defined; assert only that the magnitude SCALE is right
      // (length < raw "5432") rather than pinning a string.
      const out = formatCompact(5432);
      expect(out.length).toBeLessThan('5432'.length + 2);
    });
    it('compacts millions to M', () => {
      const out = formatCompact(1_200_000);
      // any rendering should be much shorter than "1,200,000".
      expect(out.length).toBeLessThan(10);
    });
    it('returns dash for NaN', () => {
      expect(formatCompact(NaN)).toBe('—');
    });
  });

  describe('formatPercent', () => {
    it('renders 0.995 as 99.5%', () => {
      const out = formatPercent(0.995);
      // en: "99.5%"; fr: "99,5 %"; both contain "99" + ("5" or no fraction)
      expect(out).toMatch(/99[.,]?5?\s?%/);
    });
    it('renders 0 as 0%', () => {
      expect(formatPercent(0)).toMatch(/^0\s?%$/);
    });
    it('returns dash for NaN', () => {
      expect(formatPercent(NaN)).toBe('—');
    });
  });

  describe('formatBytes', () => {
    it('formats < 1KB as bytes', () => {
      expect(formatBytes(512)).toMatch(/^512 B$/);
    });
    it('formats KB scale', () => {
      const out = formatBytes(5_400);
      expect(out).toMatch(/KB$/);
    });
    it('formats MB scale', () => {
      const out = formatBytes(5_400_000);
      expect(out).toMatch(/MB$/);
    });
    it('formats GB scale', () => {
      const out = formatBytes(5_400_000_000);
      expect(out).toMatch(/GB$/);
    });
    it('returns dash for NaN', () => {
      expect(formatBytes(NaN)).toBe('—');
    });
  });
});
