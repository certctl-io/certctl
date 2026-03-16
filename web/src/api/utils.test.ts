import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { formatDate, formatDateTime, timeAgo, daysUntil, expiryColor } from './utils';

describe('Utility functions', () => {
  describe('formatDate', () => {
    it('returns dash for empty string', () => {
      expect(formatDate('')).toBe('—');
    });

    it('formats ISO date string', () => {
      const result = formatDate('2026-06-15T12:00:00Z');
      expect(result).toContain('Jun');
      expect(result).toContain('15');
      expect(result).toContain('2026');
    });
  });

  describe('formatDateTime', () => {
    it('returns dash for empty string', () => {
      expect(formatDateTime('')).toBe('—');
    });

    it('formats ISO datetime string with time', () => {
      const result = formatDateTime('2026-06-15T14:30:00Z');
      expect(result).toContain('Jun');
      expect(result).toContain('15');
    });
  });

  describe('timeAgo', () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2026-03-15T12:00:00Z'));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('returns dash for empty string', () => {
      expect(timeAgo('')).toBe('—');
    });

    it('returns "just now" for recent times', () => {
      expect(timeAgo('2026-03-15T11:59:45Z')).toBe('just now');
    });

    it('returns minutes ago', () => {
      expect(timeAgo('2026-03-15T11:45:00Z')).toBe('15m ago');
    });

    it('returns hours ago', () => {
      expect(timeAgo('2026-03-15T09:00:00Z')).toBe('3h ago');
    });

    it('returns days ago', () => {
      expect(timeAgo('2026-03-12T12:00:00Z')).toBe('3d ago');
    });

    it('returns formatted date for old dates', () => {
      const result = timeAgo('2025-01-15T12:00:00Z');
      expect(result).toContain('2025');
    });
  });

  describe('daysUntil', () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2026-03-15T12:00:00Z'));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('returns 0 for empty string', () => {
      expect(daysUntil('')).toBe(0);
    });

    it('returns positive days for future date', () => {
      expect(daysUntil('2026-03-25T12:00:00Z')).toBe(10);
    });

    it('returns negative days for past date', () => {
      expect(daysUntil('2026-03-10T12:00:00Z')).toBeLessThan(0);
    });
  });

  describe('expiryColor', () => {
    it('returns red for expired (0 days)', () => {
      expect(expiryColor(0)).toContain('red');
    });

    it('returns red for <= 7 days', () => {
      expect(expiryColor(5)).toContain('red');
    });

    it('returns amber for <= 14 days', () => {
      expect(expiryColor(12)).toContain('amber');
    });

    it('returns amber for <= 30 days', () => {
      expect(expiryColor(25)).toContain('amber');
    });

    it('returns green for > 30 days', () => {
      expect(expiryColor(60)).toContain('emerald');
    });
  });
});
