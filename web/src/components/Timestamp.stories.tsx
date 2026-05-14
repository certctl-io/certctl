// Phase 8 TEST-H3 — Timestamp stories. Force each mode via the
// `forceMode` prop so the showroom shows all three render paths
// without depending on operator-preference localStorage state.

import type { Meta, StoryObj } from '@storybook/react';
import Timestamp from './Timestamp';

const meta = {
  title: 'Primitives/Timestamp',
  component: Timestamp,
  tags: ['autodocs'],
  args: { iso: '2026-05-14T15:30:00Z' },
} satisfies Meta<typeof Timestamp>;

export default meta;
type Story = StoryObj<typeof meta>;

export const UTCDefault: Story = { args: { forceMode: 'utc' } };
export const Local: Story = { args: { forceMode: 'local' } };
export const NullValue: Story = { args: { iso: null } };
