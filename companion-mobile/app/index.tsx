import { Redirect } from 'expo-router';
import { useStore } from '../src/lib/store';

/** first launch -> the onboarding carousel; afterwards straight to Home */
export default function Gate() {
  const onboarded = useStore((s) => s.onboarded);
  return <Redirect href={onboarded ? '/(tabs)' : '/onboarding'} />;
}
