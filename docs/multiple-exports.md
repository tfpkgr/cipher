# Guide: Creating a Package with Multiple Exports

This guide explains how to set up a package with multiple named exports using `tsup` and dynamically generate the `exports` field in `package.json`.

---

## 1️⃣ Updating `tsup.config.ts`

Modify your `tsup.config.ts` to define multiple entry points.

### Object-style entry definition:

```ts
import {defineConfig} from 'tsup';

export default defineConfig({
	entry: {
		index: 'src/index.ts',
		packageName1: 'src/packageName1/index.ts',
		packageName2: 'src/packageName2/index.ts',
	},
	format: ['esm', 'cjs'],
	tsconfig: 'tsconfig.build.json',
	outDir: 'dist',
});
```

### Array-style entry definition:

```ts
entry: [
	'src/index.ts',
	'src/packageName1/index.ts',
	'src/packageName2/index.ts',
];
```

Both styles work, and the `define-exports` script will automatically detect and process them.

---

## 2️⃣ How `define-exports` Works

The `define-exports` script dynamically updates `package.json` based on your `tsup.config.ts`.

-   If your package **only** has a single `index.ts` entry, it **adds**:

    ```json
    "main": "./dist/index.js",
    "module": "./dist/index.mjs",
    "types": "./dist/index.d.mts"
    ```

    and **skips exports generation**.

-   If your package has **multiple entry points**, it:
    -   **Removes** `main`, `module`, and `types` keys.
    -   **Generates** an `exports` field mapping each entry to the appropriate files.

> ⚠️ **Warning:** If your package has `main`, `module`, and `types` in `package.json`, and `tsup.config.ts` contains only an `index.ts` entry, the `define-exports` script will **skip processing**.

---

## 3️⃣ Example Imports

After running the script, users can import your modules like this:

### For Multiple Modules:

```js
import {packageName1} from '@tfpkgr/npm-template/packageName1';
import {packageName2} from '@tfpkgr/npm-template/packageName2';
```

### For a Single Index Module:

```js
import {defaultExport} from '@tfpkgr/npm-template';
```

---

## ✅ Conclusion

1. Supports multiple named exports automatically.
2. Ensures `package.json` stays in sync with `tsup.config.ts`.
3. Allows both **object-style** and **array-style** entry definitions.
4. Reduces manual updates by dynamically setting the correct fields.

🚀 Happy coding with MyDeck!

```

```
