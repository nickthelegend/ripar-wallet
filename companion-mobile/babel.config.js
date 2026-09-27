module.exports = function (api) {
  api.cache(true);
  return {
    presets: ['babel-preset-expo'],
    // Reanimated 4 moved the worklet transform into react-native-worklets. It has to be last.
    plugins: ['react-native-worklets/plugin'],
  };
};
