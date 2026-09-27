// Local config plugin (applied at `expo prebuild`), so the generated android/ project never needs hand edits:
//
//  1. Debug APKs carry the JS bundle (react { debuggableVariants = [] }): `./gradlew assembleDebug` produces an APK
//     that runs on a phone without a Metro dev server. With Metro running, the debug build still prefers it.
//  2. usesCleartextTraffic: a local dev stack (anvil, the agent service) is plain http on a LAN address. Public RPCs
//     are https. Testnet app: documented in README "Security model".
//  3. reactNativeArchitectures (default arm64-v8a, the phones this ships to): a quarter of the native build time and
//     APK size of all four ABIs. Override with RIPAR_ABIS="arm64-v8a,x86_64" for an x86_64 emulator.
const { withAndroidManifest, withAppBuildGradle, withGradleProperties } = require('expo/config-plugins');

module.exports = function withRiparAndroid(config) {
  config = withAppBuildGradle(config, (c) => {
    const src = c.modResults.contents;
    if (!src.includes('debuggableVariants = []')) {
      c.modResults.contents = src.replace(/react\s*\{/, 'react {\n    // ripar: bundle the JS into debug APKs too (plugins/with-ripar-android.js)\n    debuggableVariants = []\n');
    }
    return c;
  });
  config = withAndroidManifest(config, (c) => {
    const app = c.modResults.manifest.application?.[0];
    if (app) app.$['android:usesCleartextTraffic'] = 'true';
    return c;
  });
  config = withGradleProperties(config, (c) => {
    const abis = process.env.RIPAR_ABIS || 'arm64-v8a';
    const props = c.modResults.filter((p) => !(p.type === 'property' && p.key === 'reactNativeArchitectures'));
    props.push({ type: 'property', key: 'reactNativeArchitectures', value: abis });
    c.modResults = props;
    return c;
  });
  return config;
};
