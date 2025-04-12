const fs = require('node:fs');
const path = require('node:path');

// Load package.json
const packageJsonPath = path.resolve(__dirname, '../package.json');
const packageJson = require(packageJsonPath);

// Path to tsup config
const tsupConfigPath = path.resolve(__dirname, '../tsup.config.ts');
const tsupConfig = fs.readFileSync(tsupConfigPath, 'utf-8');

// Extract `entry` field using regex
const entryMatch = tsupConfig.match(/entry:\s*(\{[^}]+\}|\[[^\]]+\])/);

if (!entryMatch) {
	console.error('❌ Could not find `entry` field in tsup.config.ts');
	throw new Error('Could not find `entry` field in tsup.config.ts');
}

const entryContent = entryMatch[1].trim();

// Parse entries
let entries = {};

// Handle object-style entry definition: `{ 'p1/index': "src/p1/index.ts", '@p2/index': "src/p2/index.ts" }`
if (entryContent.startsWith('{')) {
	entryContent
		.slice(1, -1)
		.split(',')
		.forEach(line => {
			const parts = line
				.split(':')
				.map(part => part.trim().replace(/['"]/g, ''));
			if (parts.length === 2) {
				entries[parts[0]] = parts[1]; // Key = module name, Value = file path
			}
		});
}

// Handle array-style entry definition: `[ "src/index.ts", "src/p1/index.ts", "src/@p2/index.ts" ]`
if (entryContent.startsWith('[')) {
	const paths = entryContent
		.slice(1, -1)
		.split(',')
		.map(filePath => filePath.trim().replace(/['"]/g, ''));

	entries = Object.fromEntries(
		paths.map(filePath => {
			const cleanPath = filePath
				.replace(/^src\//, '')
				.replace(/\.ts$/, '');
			return [cleanPath, filePath];
		}),
	);
}

// Check if the project has only a single index file
const hasOnlyIndex = Object.keys(entries).length === 1 && entries['index'];

if (hasOnlyIndex) {
	// Dynamically set main, module, and types
	packageJson.main = './dist/index.js';
	packageJson.module = './dist/index.mjs';
	packageJson.types = './dist/index.d.mts';

	// Remove exports and typesVersions if they exist
	if (packageJson.exports) delete packageJson.exports;
	if (packageJson.typesVersions) delete packageJson.typesVersions;

	fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 4));
	console.log(
		'✅ Skipping exports generation: Single index file detected. Main, module, and types fields added.',
	);
	return;
}

// Remove main, module, and types fields for multi-module packages
if (packageJson.main) delete packageJson.main;
if (packageJson.module) delete packageJson.module;
if (packageJson.types) delete packageJson.types;

// Generate `exports` and `typesVersions`
const exp = {};
const typesVersions = {'*': {}};

Object.entries(entries).forEach(([key, value]) => {
	// Ensure that empty keys are not created
	if (!key || key.trim() === '') {
		console.warn(`⚠️ Skipping empty export entry for path: ${value}`);
		return;
	}

	// Ensure module path follows `./module` format
	let modulePath = `./${key.replace(/\/index$/, '')}`; // Remove `/index` suffix

	// Check if the module path is './index'
	if (modulePath === './index') {
		modulePath = '.'; // Set to root if it's the index
	}

	const exportConfig = {
		types: `./dist/${key}.d.mts`,
		import: `./dist/${key}.mjs`,
		require: `./dist/${key}.js`,
	};

	exp[modulePath] = exportConfig;
	typesVersions['*'][modulePath] = [`dist/${key}.d.mts`];
});

// Update package.json with exports
packageJson.exports = exp;
packageJson.typesVersions = typesVersions;

// Write back to package.json
fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 4));

console.log('✅ Successfully updated package.json with exports!');
