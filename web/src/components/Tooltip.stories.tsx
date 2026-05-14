// Phase 8 TEST-H3 — Tooltip stories. Render with a button trigger so
// the showroom user can hover/focus to see the Floating-UI positioning
// + the aria-describedby wiring the addon-a11y test validates.

import type { Meta, StoryObj } from '@storybook/react';
import Tooltip from './Tooltip';

const meta = {
  title: 'Primitives/Tooltip',
  component: Tooltip,
  tags: ['autodocs'],
} satisfies Meta<typeof Tooltip>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Top: Story = {
  args: {
    content: 'Triggers a CRL refresh on every replica',
    placement: 'top',
    children: <button className="btn btn-outline">Hover me</button>,
  },
};

export const Bottom: Story = {
  args: {
    content: 'Soft-retires the agent (reversible only via direct DB)',
    placement: 'bottom',
    children: <button className="btn btn-outline">Hover me</button>,
  },
};
