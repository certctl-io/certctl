// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Zod schema for the inline "Create Team" form inside CertificateStep
// (the wizard's third step). Phase 5 closure scaffolding for FE-M1 +
// UX-H4 — proves the FormField + react-hook-form + zodResolver pattern
// on a small, contained form that's part of the operator's first-run
// experience.
//
// Backend contract: POST /api/v1/teams accepts `{ name: string,
// description?: string }`. Name is required (handler 400s on empty);
// description is optional. We mirror that here so submit-time
// validation matches what the server will accept.

import { z } from 'zod';

// Both fields typed as string (no `optional()`) so the schema's input
// and output types match — RHF + zodResolver require Input == Output
// when the resolver TFieldValues generic is invariant. Description
// defaults to '' from the form's defaultValues; the backend treats
// empty-string and absent identically (handler at internal/api/handler/
// teams.go:34 calls strings.TrimSpace before checking len).
export const teamSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, 'Team name is required'),
  description: z
    .string()
    .trim(),
});

export type TeamFormValues = z.infer<typeof teamSchema>;
