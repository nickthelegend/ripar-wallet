// Network settings: the RPC (Monad testnet or a local dev stack), the Ripar deployments JSON (URL or paste), a dev
// stack description (scripts/dev-stack.sh writes stack.json), and the agent service. Ported from Connect.tsx.
import { useState } from 'react';
import { StyleSheet, TextInput, View } from 'react-native';
import { checkDeploymentPins, parseDeployment } from '@ripar/protocol';
import { Button, Label, Note, Pill, Screen, Surface, Text } from '../src/components';
import { agentClientOf } from '../src/lib/agent';
import { refreshChain } from '../src/lib/chainState';
import { publicClientFor } from '../src/lib/clients';
import { errorText } from '../src/lib/format';
import { isRecord } from '../src/lib/json';
import { NETWORKS, type NetworkId } from '../src/lib/networks';
import { checkContracts } from '../src/lib/reads';
import { deploymentOf, store, useStore } from '../src/lib/store';
import { ink, palette, radius, space } from '../src/theme';

function Field({ label, value, onChange, placeholder, multiline, secure }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string; multiline?: boolean; secure?: boolean }) {
  return (
    <View style={{ gap: 6 }}>
      <Label>{label}</Label>
      <TextInput
        value={value}
        onChangeText={onChange}
        placeholder={placeholder}
        placeholderTextColor={ink.faint}
        autoCapitalize="none"
        autoCorrect={false}
        multiline={multiline}
        secureTextEntry={secure}
        style={[styles.input, multiline && { minHeight: 110, textAlignVertical: 'top' }]}
        accessibilityLabel={label}
      />
    </View>
  );
}

export default function Network() {
  const settings = useStore((s) => s.settings);
  const dep = deploymentOf(settings);
  const [rpc, setRpc] = useState(settings.rpcUrl);
  const [depUrl, setDepUrl] = useState(settings.deploymentsUrl);
  const [paste, setPaste] = useState('');
  const [stackUrl, setStackUrl] = useState('');
  const [agentUrl, setAgentUrl] = useState(settings.agentUrl);
  const [agentToken, setAgentToken] = useState(settings.agentToken);
  const [msg, setMsg] = useState<{ tone: 'good' | 'bad'; text: string } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const pick = (id: NetworkId) => {
    const n = NETWORKS[id];
    store.setSettings({ network: id, rpcUrl: n.rpcUrl, chainId: n.chainId });
    setRpc(n.rpcUrl);
  };

  const check = async () => {
    setBusy('check');
    setMsg(null);
    try {
      store.setSettings({ rpcUrl: rpc.trim() });
      const pc = publicClientFor({ ...store.get().settings, rpcUrl: rpc.trim() });
      const id = await pc.getChainId();
      if (id !== 10143 && id !== 143) throw new Error(`chain ${id}: the Ripar knows only 10143 and 143`);
      store.setSettings({ chainId: id });
      const d = deploymentOf(store.get().settings).deployment;
      let extra = '';
      if (d) {
        const codes = await checkContracts(pc, d);
        const missing = codes.filter((c) => c.bytes === 0).map((c) => c.name);
        extra = missing.length ? ` Missing code: ${missing.join(', ')}.` : ' Every Ripar contract has code.';
      }
      setMsg({ tone: 'good', text: `Chain ${id} answers.${extra}` });
      void refreshChain();
    } catch (e) {
      setMsg({ tone: 'bad', text: errorText(e) });
    } finally {
      setBusy(null);
    }
  };

  const applyDeployment = (text: string, url = '') => {
    const d = parseDeployment(text, store.get().settings.chainId);
    store.setSettings({ deploymentsJson: JSON.stringify(JSON.parse(text), null, 2), deploymentsUrl: url });
    const pins = checkDeploymentPins(d).filter((x) => x.key !== 0);
    setMsg({ tone: pins.length ? 'bad' : 'good', text: pins.length ? `Loaded, but the Ripar would refuse it: ${pins.map((x) => x.name).join(', ')} differ from the firmware.` : 'Deployment loaded: the contracts are the ones compiled into the firmware.' });
    void refreshChain();
  };

  const fetchJson = async (url: string): Promise<string> => {
    const r = await fetch(url, { headers: { accept: 'application/json' } });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.text();
  };

  const loadStack = async () => {
    setBusy('stack');
    setMsg(null);
    try {
      const x = JSON.parse(await fetchJson(stackUrl.trim())) as unknown;
      if (!isRecord(x) || !isRecord(x.deployments)) throw new Error('not a dev-stack stack.json (no deployments)');
      const chainId = x.chainId === 143 ? 143 : 10143;
      // the stack describes 127.0.0.1 URLs of the computer: keep the host this phone reached stack.json on (regexes,
      // not URL setters: React Native's URL has no setters)
      const host = /^https?:\/\/([^/:?#]+)/i.exec(stackUrl.trim())?.[1];
      if (!host) throw new Error('stack.json URL: not http(s)');
      const swap = (u: unknown) =>
        typeof u === 'string' && /^https?:\/\//i.test(u) ? u.replace(/^(https?:\/\/)(127\.0\.0\.1|localhost)(?=[:/]|$)/i, `$1${host}`).replace(/\/$/, '') : null;
      parseDeployment(x.deployments, chainId);
      const rpcUrl = swap(x.rpcUrl) ?? rpc;
      const ag = swap(x.agentUrl) ?? agentUrl;
      store.setSettings({ network: 'local', rpcUrl, chainId, agentUrl: ag, deploymentsJson: JSON.stringify(x.deployments, null, 2), deploymentsUrl: '' });
      setRpc(rpcUrl);
      setAgentUrl(ag);
      setMsg({ tone: 'good', text: `Dev stack applied: RPC ${rpcUrl}, agent ${ag}.` });
      void refreshChain();
    } catch (e) {
      setMsg({ tone: 'bad', text: errorText(e) });
    } finally {
      setBusy(null);
    }
  };

  const checkAgent = async () => {
    setBusy('agent');
    setMsg(null);
    try {
      store.setSettings({ agentUrl: agentUrl.trim(), agentToken: agentToken.trim() });
      const h = await agentClientOf({ agentUrl: agentUrl.trim(), agentToken: agentToken.trim() }).health();
      setMsg({ tone: 'good', text: `Agent ${h.agent?.address ?? '(no address)'} on chain ${h.chainId ?? '?'}${h.mandate ? `, holds mandate ${h.mandate.delegationHash.slice(0, 10)}…` : ', no mandate yet'}.` });
    } catch (e) {
      setMsg({ tone: 'bad', text: errorText(e) });
    } finally {
      setBusy(null);
    }
  };

  return (
    <Screen back eyebrow="Settings" title="Network" tabs={false}>
      <View style={{ gap: space.lg }}>
        <View style={{ flexDirection: 'row', gap: space.sm }}>
          {(Object.keys(NETWORKS) as NetworkId[]).map((id) => (
            <Pill key={id} label={NETWORKS[id].label} tone={settings.network === id ? 'signal' : 'plain'} onPress={() => pick(id)} />
          ))}
        </View>
        <Text variant="bodySmall" tone="soft">
          {NETWORKS[settings.network].note}
        </Text>

        <Surface padded={16} style={{ gap: space.md }}>
          <Field label="RPC URL" value={rpc} onChange={setRpc} placeholder="https://testnet-rpc.monad.xyz" />
          <Button label="Save and check" variant="secondary" loading={busy === 'check'} onPress={() => void check()} />
        </Surface>

        <Surface padded={16} style={{ gap: space.md }}>
          <Label>Ripar deployment</Label>
          {dep.deployment ? (
            <Text variant="bodySmall" tone="success">
              Loaded for chain {dep.deployment.chainId.toString()}: registry {dep.deployment.registry.slice(0, 10)}…, sentinel {dep.deployment.sentinel.slice(0, 10)}…
            </Text>
          ) : (
            <Text variant="bodySmall" tone={dep.error ? 'danger' : 'soft'}>
              {dep.error ?? 'None yet: contracts/deployments/<chainId>.json from contracts/script/Deploy.s.sol.'}
            </Text>
          )}
          <Field label="Fetch from a URL" value={depUrl} onChange={setDepUrl} placeholder="https://.../10143.json" />
          <Button
            label="Fetch"
            variant="secondary"
            loading={busy === 'dep'}
            onPress={async () => {
              setBusy('dep');
              setMsg(null);
              try {
                applyDeployment(await fetchJson(depUrl.trim()), depUrl.trim());
              } catch (e) {
                setMsg({ tone: 'bad', text: errorText(e) });
              } finally {
                setBusy(null);
              }
            }}
          />
          <Field label="Or paste the JSON" value={paste} onChange={setPaste} multiline placeholder='{"chainId":10143,"RiparDeviceRegistry":"0x..."}' />
          <Button
            label="Use pasted JSON"
            variant="secondary"
            onPress={() => {
              try {
                applyDeployment(paste);
              } catch (e) {
                setMsg({ tone: 'bad', text: errorText(e) });
              }
            }}
          />
        </Surface>

        <Surface padded={16} style={{ gap: space.md }}>
          <Label>Local dev stack</Label>
          <Text variant="bodySmall" tone="soft">
            scripts/dev-stack.sh serves companion/public/devstack/stack.json. Give its URL on your computer's LAN address (e.g. http://192.168.1.20:5173/devstack/stack.json).
          </Text>
          <Field label="stack.json URL" value={stackUrl} onChange={setStackUrl} placeholder="http://192.168.x.x:5173/devstack/stack.json" />
          <Button label="Apply the dev stack" variant="secondary" loading={busy === 'stack'} onPress={() => void loadStack()} />
        </Surface>

        <Surface padded={16} style={{ gap: space.md }}>
          <Label>Agent service (optional)</Label>
          <Field label="Agent URL" value={agentUrl} onChange={setAgentUrl} placeholder="http://192.168.x.x:8787" />
          <Field label="API token (AGENT_API_TOKEN, if set)" value={agentToken} onChange={setAgentToken} secure />
          <Button label="Save and check the agent" variant="secondary" loading={busy === 'agent'} onPress={() => void checkAgent()} />
        </Surface>

        {msg && <Note tone={msg.tone}>{msg.text}</Note>}
      </View>
    </Screen>
  );
}

const styles = StyleSheet.create({
  input: {
    backgroundColor: palette.cardHigh,
    color: palette.foreground,
    borderRadius: radius.md,
    borderWidth: 1,
    borderColor: ink.hairline,
    paddingHorizontal: space.md,
    paddingVertical: 10,
    fontFamily: 'JetBrainsMono_400Regular',
    fontSize: 12,
  },
});
