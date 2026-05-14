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
    severity: 'error',
    children: 'Failed to issue certificate — CA rejected the CSR (RFC 5280 §4.2.1.6 SAN violation).',
  },
};

export const Warning: Story = {
  args: {
    severity: 'warning',
    children: 'This issuer is in maintenance mode — new issuance requests will queue.',
  },
};

export const Success: Story = {
  args: {
    severity: 'success',
    children: 'Renewal complete. New certificate deployed to 3 targets.',
  },
};

export const Info: Story = {
  args: {
    severity: 'info',
    children: 'Approval requested. Awaiting sign-off from a different operator.',
  },
};
