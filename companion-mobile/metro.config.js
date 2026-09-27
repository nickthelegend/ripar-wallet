// Metro for a standalone Expo app that uses the repo's protocol library from source.
//
// companion-mobile is NOT an npm workspace of the repo root (Expo wants its own hoisted node_modules, and the web
// companion / agent pin other React and tooling versions). @ripar/protocol is therefore resolved here, by path, to
// ../packages/protocol/src (TypeScript source, always current, no build step), and every bare import made from inside
// that folder (viem, @noble/*) is resolved from THIS app's node_modules, so the bundle carries exactly one copy of
// viem and noble. The protocol's NodeNext-style "./x.js" imports are mapped to their "./x.ts" sources.
const path = require('path');
const { getDefaultConfig } = require('expo/metro-config');

const projectRoot = __dirname;
const protocolRoot = path.resolve(projectRoot, '../packages/protocol');
const protocolSrc = path.join(protocolRoot, 'src');
const protocolEntry = path.join(protocolSrc, 'index.ts');
const anchor = path.join(projectRoot, 'package.json');

const config = getDefaultConfig(projectRoot);
config.watchFolders = [protocolSrc];
config.resolver.nodeModulesPaths = [path.join(projectRoot, 'node_modules')];

const inProtocol = (p) => !!p && path.resolve(p).startsWith(protocolSrc + path.sep);

config.resolver.resolveRequest = (context, moduleName, platform) => {
  if (moduleName === '@ripar/protocol') return { type: 'sourceFile', filePath: protocolEntry };
  if (inProtocol(context.originModulePath)) {
    if (moduleName.startsWith('.')) {
      const ts = path.resolve(path.dirname(context.originModulePath), moduleName.replace(/\.js$/, '.ts'));
      if (moduleName.endsWith('.js')) return { type: 'sourceFile', filePath: ts };
    } else {
      // bare import from the protocol source: resolve it as if this app imported it
      return context.resolveRequest({ ...context, originModulePath: anchor }, moduleName, platform);
    }
  }
  return context.resolveRequest(context, moduleName, platform);
};

module.exports = config;
