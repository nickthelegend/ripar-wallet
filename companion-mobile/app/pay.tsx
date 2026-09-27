// One payment from the vault: build the co-sign request (fresh single-use nonce, 15 min expiry), the device reviews it
// (pulse + SIGN), the answer is verified against the request and the device's P1 key, then this phone's key redeems
// the personal mandate with the device's co-sign args (HUMAN path) and pays the gas. Every step is persisted, so
// leaving the screen or restarting the app resumes the same round.
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useEffect, useMemo, useRef, useState } from 'react';
import { View } from 'react-native';
import type { Hex } from 'viem';
import { Address, Button, DeviceRound, Label, Note, Screen, Spec, Surface, Text } from '../src/components';
import { verifierOf } from '../src/device/link';
import { sendWrite } from '../src/lib/chain';
import { refreshChain } from '../src/lib/chainState';
import { connectCourier, publicClientFor } from '../src/lib/clients';
import { remergePayments } from '../src/lib/feed';
import { type CosignOutcome, acceptCosignAnswer, answersCosign } from '../src/lib/flows/cosign';
import { planFromRequestUr, planPayment, redeemPaymentWrite } from '../src/lib/flows/personal';
import { amountText, errorText, utcText } from '../src/lib/format';
import { hotKeyAddress } from '../src/lib/hotkey';
import { rememberNonce, updatePayment } from '../src/lib/payments';
import { nonceUsed } from '../src/lib/reads';
import { previewCosign } from '../src/lib/review-preview';
import { rememberedMandate, store, useStore } from '../src/lib/store';
import { space } from '../src/theme';

export default function Pay() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const router = useRouter();
  const payment = useStore((s) => s.payments.find((p) => p.id === id) ?? null);
  const device = useStore((s) => s.device);
  const personal = useStore((s) => s.personal);
  const settings = useStore((s) => s.settings);
  const [err, setErr] = useState<string | null>(null);
  const [redeeming, setRedeeming] = useState<string | null>(null);

  // 1. the request (built once; a restart resumes it from the stored UR)
  const building = useRef<string | null>(null);
  useEffect(() => {
    if (!payment || !device || !personal || payment.status !== 'building') return;
    // one build per round, even when the store updates while it runs
    const round = `${payment.id}:${payment.createdAt}:${payment.requestUr}`;
    if (building.current === round) return;
    building.current = round;
    let live = true;
    (async () => {
      try {
        const pc = publicClientFor(settings);
        const hot = await hotKeyAddress();
        const dh = personal.delegationHash;
        const plan = await planPayment(
          { to: payment.to, asset: payment.asset, amount: BigInt(payment.amount) },
          {
            device,
            personal,
            hotKey: hot,
            handedOut: store.get().nonces[dh.toLowerCase()] ?? [],
            usedOnChain: async (n) => {
              try {
                return await nonceUsed(pc, device.pinned.enforcer, dh, n);
              } catch (e) {
                throw new Error(`Cannot confirm on-chain that nonce ${n} is unused (${errorText(e)}). Nothing was shown to the device.`);
              }
            },
            now: Math.floor(Date.now() / 1000),
            fragLen: settings.fragLen,
          },
        );
        rememberNonce(dh, plan.nonce);
        // stored even if this effect was superseded meanwhile: the build guard allows one build per round
        updatePayment(payment.id, { status: 'on-device', requestUr: plan.request.ur, nonce: plan.nonce.toString() });
      } catch (e) {
        building.current = null;
        if (live) setErr(errorText(e));
      }
    })();
    return () => {
      live = false;
    };
  }, [payment, device, personal, settings]);

  const plan = useMemo(() => {
    if (!payment?.requestUr) return null;
    try {
      return planFromRequestUr(payment.requestUr, settings.fragLen);
    } catch {
      return null;
    }
  }, [payment?.requestUr, settings.fragLen]);

  const remembered = useStore(rememberedMandate);
  const preview = useMemo(
    () =>
      plan && device && personal
        ? previewCosign(plan.decoded, {
            p1Key: device.p1Key,
            vault: device.pinned.vault,
            sentinel: device.pinned.sentinel,
            minEpoch: 0n,
            lastDelegationHash: store.get().lastSignedMandate,
            lastMandatePulseTerms: remembered?.pulseTerms ?? null,
            panicAfterMandate: false,
          })
        : null,
    [plan, device, personal, remembered],
  );

  const verifier = useMemo(
    () =>
      plan && device
        ? verifierOf<CosignOutcome>(['ripar-cosign', 'ripar-deny'], (ur) => acceptCosignAnswer(ur, plan, device, personal), (ur) => answersCosign(ur, plan.request))
        : null,
    [plan, device, personal],
  );

  // 3. redeem: the hot key sends redeemDelegations with the device's co-sign args
  const redeem = async (caveatArgs: Hex) => {
    if (!payment || !plan || !personal || !device) return;
    setErr(null);
    setRedeeming('Estimating gas...');
    try {
      const pc = publicClientFor(settings);
      const courier = await connectCourier(settings);
      let w = redeemPaymentWrite(personal, plan, caveatArgs, { manager: device.pinned.manager, enforcer: device.pinned.enforcer });
      try {
        const est = await pc.estimateGas({ account: courier.account, to: w.to, data: w.data });
        w = { ...w, gas: est + est / 4n };
      } catch {
        /* keep the fixed limit: sendWrite simulates and explains a revert before anything is paid */
      }
      updatePayment(payment.id, { status: 'cosigned' });
      const r = await sendWrite(pc, courier, w, (s, h) => {
        setRedeeming(s === 'simulating' ? 'Checking it would succeed...' : s === 'signing' ? 'Signing with the phone key...' : s === 'pending' ? 'Waiting for the block...' : 'Confirmed');
        if (h) updatePayment(payment.id, { tx: h, status: 'sent' });
      });
      updatePayment(payment.id, { status: 'confirmed', tx: r.hash, doneAt: Date.now() });
      remergePayments();
      void refreshChain();
      router.replace({ pathname: '/done', params: { id: payment.id } });
    } catch (e) {
      const m = errorText(e);
      updatePayment(payment.id, { status: 'cosigned', error: m });
      setErr(/insufficient funds|exceeds the balance/i.test(m) ? `${m}. The phone key needs testnet MON for gas (Settings > Phone key).` : m);
    } finally {
      setRedeeming(null);
    }
  };

  if (!payment || !device || !personal) {
    return (
      <Screen back title="Payment" tabs={false}>
        <Note tone="bad">This payment is not available any more.</Note>
      </Screen>
    );
  }

  const amount = amountText(BigInt(payment.amount), payment.decimals, payment.symbol);
  const expired = !!plan && plan.expiry <= BigInt(Math.floor(Date.now() / 1000)) && payment.status === 'on-device';
  const cosignArgs = payment.cosignUr && plan ? safeArgs(payment.cosignUr) : null;

  function safeArgs(ur: string): Hex | null {
    try {
      const o = acceptCosignAnswer(ur, plan!, device!, personal);
      return o.kind === 'cosign' ? o.answer.caveatArgs : null;
    } catch {
      return null;
    }
  }

  return (
    <Screen back eyebrow="Co-signed payment" title={amount} lede={`To ${payment.to.slice(0, 10)}…${payment.to.slice(-6)}`} tabs={false}>
      <View style={{ gap: space.lg }}>
        {payment.status === 'building' && !err && <Text tone="soft">Preparing the request (a fresh single-use nonce, checked on-chain)...</Text>}

        {payment.status === 'on-device' && plan && verifier && !expired && (
          <>
            {preview && (
              <Surface padded={16} style={{ gap: space.sm }}>
                <Label>What your Ripar will show</Label>
                {preview.lines.slice(0, 14).map((l, i) => (
                  <View key={`${i}:${l.label}`} style={{ flexDirection: 'row', gap: space.sm }}>
                    <Text variant="monoSmall" tone="faint" style={{ width: 86 }}>
                      {l.label}
                    </Text>
                    <Text variant="monoSmall" tone={l.tone === 'bad' ? 'danger' : l.tone === 'warn' ? 'warn' : l.tone === 'good' ? 'success' : 'default'} style={{ flex: 1 }}>
                      {l.value}
                    </Text>
                  </View>
                ))}
                <Text variant="bodySmall" tone="faint">
                  If the Ripar shows anything else, hold SIGN 2 s: nothing is signed.
                </Text>
              </Surface>
            )}
            <DeviceRound
              request={plan.request}
              verifier={verifier}
              kind="cosign"
              runKey={plan.request.reqId}
              onVerified={(o, ur) => {
                if (o.kind === 'deny') {
                  updatePayment(payment.id, { status: 'denied', cosignUr: ur, doneAt: Date.now() });
                  remergePayments();
                  return;
                }
                updatePayment(payment.id, { cosignUr: ur, bpm: o.bpm, status: 'cosigned' });
                void redeem(o.answer.caveatArgs);
              }}
            />
          </>
        )}

        {expired && (
          <Note tone="warn" title="This request expired">
            A co-sign request is valid for 15 minutes. Start a new one: it gets a fresh nonce.
          </Note>
        )}
        {expired && (
          <Button
            label="New request"
            onPress={() => {
              building.current = null;
              updatePayment(payment.id, { status: 'building', requestUr: '', nonce: '', createdAt: Date.now() });
            }}
          />
        )}

        {(payment.status === 'cosigned' || payment.status === 'sent') && (
          <Surface padded={18} style={{ gap: space.md }}>
            <Label>Co-signed on your Ripar{payment.bpm ? ` · pulse ${payment.bpm} bpm` : ''}</Label>
            <Text tone="soft">{redeeming ?? (payment.tx ? 'Sent; waiting for the receipt.' : 'Ready to send from the vault.')}</Text>
            {!redeeming && cosignArgs && <Button label={payment.error ? 'Send again' : 'Send'} onPress={() => void redeem(cosignArgs)} />}
          </Surface>
        )}

        {payment.status === 'denied' && (
          <Note tone="bad" title="Denied on your Ripar">
            You refused this payment on the device. Nothing was signed for it and nothing was sent.
          </Note>
        )}
        {payment.status === 'confirmed' && <Button label="Show the receipt" onPress={() => router.replace({ pathname: '/done', params: { id: payment.id } })} />}

        {err && (
          <Note tone="bad" title="Not sent">
            {err}
          </Note>
        )}

        <Surface padded={16}>
          <Spec
            rows={[
              { k: 'To', v: <Address value={payment.to} label="Payee" /> },
              { k: 'From your vault', v: <Address value={device.pinned.vault} label="Vault" tone="soft" /> },
              plan && { k: 'Nonce (single-use)', v: plan.nonce.toString() },
              plan && { k: 'Expires', v: utcText(plan.expiry) },
              { k: 'Signed by', v: 'your Ripar (P-256, after pulse + SIGN); redeemed by this phone’s key' },
            ]}
          />
        </Surface>
      </View>
    </Screen>
  );
}
