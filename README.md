# @tfpkgr/package-name

A standardized TypeScript-based npm package template with automatic bundling using **tsup**.

## Features

-   **TypeScript support**: Ensures type safety and maintainability.
-   **Automatic bundling**: Uses `tsup` to bundle TypeScript into CommonJS (CJS) and ECMAScript Module (ESM) formats.
-   **Google TypeScript Style**: Enforces code consistency with `gts`.
-   **GitHub Packages Registry**: Pre-configured for publishing to GitHub Packages.
-   **Linting & Formatting**: Includes `gts` for linting and auto-fixing code style issues.
-   **GitHub Actions**: Automated publishing workflow on release.

## Getting Started

### 1. Clone the Repository

```sh
npx degit tfpkgr/template-npm my-new-package
cd my-new-package
```

### 2. Rename the Package

Before installing dependencies, update the `name` field in `package.json` to your package name. This ensures `package-lock.json` is correctly updated when you install dependencies.

### 3. Install Dependencies

```sh
npm install
```

### 4. Customize Package

-   Update `package.json` with the appropriate `description` and `author`.
-   Modify `src/index.ts` to implement your package functionality.

### 5. Build the Package

```sh
npm run build
```

This will generate the `dist/` directory containing the compiled files.

### 6. Lint & Fix Code

```sh
npm run lint  # Check for issues
npm run fix   # Auto-fix issues
```

### 7. Publish to GitHub Packages

#### Automatic Publishing on Release

This repository includes a GitHub Actions workflow (`.github/workflows/publish.yaml`) that automatically publishes the package when a release is created.

#### Manual Publishing

1. Authenticate with GitHub:
    ```sh
    npm login --registry=https://npm.pkg.github.com
    ```
2. Publish the package:
    ```sh
    npm publish
    ```

## File Structure

```
my-new-package/
├── src/              # Source TypeScript files
│   ├── index.ts      # Main entry point
├── dist/             # Compiled output (ignored in Git)
├── .github/workflows/ # GitHub Actions workflow for publishing
│   ├── publish.yaml  # Publish package on release
├── tsconfig.json     # TypeScript configuration
├── tsconfig.build.json # Build-specific TypeScript config
├── tsup.config.ts    # tsup bundler config
├── package.json      # Project metadata & dependencies
├── README.md         # Project documentation
├── LICENSE           # License file
```

## [Multiple Exports](docs/multiple-exports.md)

If your package has multiple exports, refer to [this guide](docs/multiple-exports.md) for configuration details.

## License

This project is licensed under the [MIT License](LICENSE).

---

🚀 Built with ❤️ by MyDeck
