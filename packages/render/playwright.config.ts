// SPDX-FileCopyrightText: 2026 tao3k team and Contributors
//
// SPDX-License-Identifier: LGPL-2.1-or-later

import { defineConfig } from 'playwright/test';
export default defineConfig({
  testDir: './test',
  testMatch: '**/*.browser.ts',
  workers: 2,
  fullyParallel: false,
  reporter: 'line',
  outputDir: '../../.cache/render/playwright',
});
