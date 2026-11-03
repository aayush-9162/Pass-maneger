import { resolve } from 'node:path';
import { defineConfig } from 'vite';

/**
 * Content-script build.
 *
 * Emitted as a self-contained IIFE with no code splitting: content scripts are
 * injected as classic scripts into the page's isolated world, where `import`
 * is unavailable and a chunked build would simply fail to load.
 *
 * `emptyOutDir: false` so this second pass does not delete the output of the
 * first one.
 */
export default defineConfig({
  resolve: {
    alias: { '@': resolve(__dirname, 'src') },
  },

  /**
   * Do not copy `public/` again.
   *
   * The first pass already copied it, and copying a second time overwrites the
   * manifest that pass had just rewritten - which silently undid the removal of
   * the `_comment_*` documentation keys and put the Chrome warnings back.
   */
  publicDir: false,

  build: {
    outDir: 'dist',
    emptyOutDir: false,
    // Left unminified deliberately: this is the script injected into every page
    // the user visits, so it is the one file a reviewer should be able to read
    // top to bottom without a source map.
    minify: false,
    sourcemap: true,
    target: 'chrome111',

    lib: {
      entry: resolve(__dirname, 'src/content/autofill.ts'),
      name: 'PassMContent',
      formats: ['iife'],
      fileName: () => 'content.js',
    },
  },
});
