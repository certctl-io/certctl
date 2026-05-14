// Phase 8 TEST-H3 — FormField stories.
// The addon-a11y signal here is load-bearing: any future regression
// that breaks the htmlFor↔id auto-binding will show as an axe
// violation in the Storybook UI before it reaches an operator's
// screen reader.

import type { Meta, StoryObj } from '@storybook/react';
import FormField from './FormField';

const meta = {
  title: 'Primitives/FormField',
  component: FormField,
  tags: ['autodocs'],
} satisfies Meta<typeof FormField>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Basic: Story = {
  args: {
    label: 'Email',
    children: <input type="email" placeholder="alice@example.com" /> as never,
  },
};

export const Required: Story = {
  args: {
    label: 'Display name',
    required: true,
    children: <input type="text" /> as never,
  },
};

export const WithDescription: Story = {
  args: {
    label: 'API key',
    description: 'Paste the bearer token from /auth/keys',
    children: <input type="password" /> as never,
  },
};

export const WithError: Story = {
  args: {
    label: 'Email',
    required: true,
    error: 'Must be a valid email address',
    children: <input type="email" defaultValue="not-an-email" /> as never,
  },
};

export const Textarea: Story = {
  args: {
    label: 'Description',
    description: 'What does this team own? (optional)',
    children: <textarea rows={4} /> as never,
  },
};
