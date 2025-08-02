import { defineConfig } from 'vite';

export default defineConfig({
	build: {
		lib: {
			entry: 'src/consent.js',
			name: 'ConsentScript',
			fileName: () => 'consent.js',
			formats: ['iife'] // needed for content scripts (plain <script> style)
		},
		outDir: 'dist',
		rollupOptions: {
			output: {
				entryFileNames: 'consent.js'
			}
		}
	}
});
