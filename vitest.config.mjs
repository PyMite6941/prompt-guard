import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		// `npm run build` (tsc) runs inside cli.test.ts beforeAll and can take
		// longer than vitest's default 10s hook timeout on slower machines.
		hookTimeout: 60000,
	},
});
