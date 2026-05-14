// Phase 8 TEST-H3 — Banner stories. One story per severity surfaces
// the 4-tier visual catalog + the role=alert / role=status semantics
// the a11y addon validates per render.

import type { Meta, StoryObj } from '@storybook/react';
import Banner from './Banner';

const meta = {
  title: 'Primitives/Banner',
  component: Banner,
  tags: ['autodocs'],
} satisfies Meta<typeof Banner>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Error: Story = {
  args: {
    type: 'error',
    children: 'Failed to issue certificate — CA rejected the CSR (RFC 5280 §4.2.1.6 SAN violation).',
  },
};

export const Warning: Story = {
  args: {
    type: 'warning',
    children: 'This issuer is in maintenance mode — new issuance requests will queue.',
  },
};

export const Success: Story = {
  args: {
    type: 'success',
    children: 'Renewal complete. New certificate deployed to 3 targets.',
  },
};

export const Info: Story = {
  args: {
    type: 'info',
    children: 'Approval requested. Awaiting sign-off from a different operator.',
  },
};
