// Phase 8 TEST-H3 — EmptyState stories. The first-run CTA shape
// drives operator onboarding for ~12 list pages; pinning the variants
// here keeps the call-to-action contract visible at design-review time.

import type { Meta, StoryObj } from '@storybook/react';
import EmptyState from './EmptyState';

const meta = {
  title: 'Primitives/EmptyState',
  component: EmptyState,
  tags: ['autodocs'],
} satisfies Meta<typeof EmptyState>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Minimal: Story = {
  args: {
    title: 'No certificates yet',
  },
};

export const WithDescription: Story = {
  args: {
    title: 'No certificates yet',
    description: 'Issue your first certificate to start tracking renewals.',
  },
};

export const PrimaryAction: Story = {
  args: {
    title: 'No certificates yet',
    description: 'Issue your first certificate to start tracking renewals.',
    primaryAction: { label: 'Issue certificate', onClick: () => {} },
  },
};

export const PrimaryPlusSecondary: Story = {
  args: {
    title: 'No certificates yet',
    description: 'Either issue a new cert, or connect an existing CA to import them.',
    primaryAction: { label: 'Issue certificate', onClick: () => {} },
    secondaryAction: { label: 'Connect an issuer', onClick: () => {} },
  },
};
