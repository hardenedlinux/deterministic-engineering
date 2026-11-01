import { defineConfig } from 'playwright/test';
export default defineConfig({
  testDir: './test',
  testMatch: '**/*.browser.ts',
  workers: 2,
  fullyParallel: false,
  reporter: 'line',
  outputDir: '../../.cache/render/playwright',
});
