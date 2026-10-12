import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSafeLookup, isPublicAuditAddress } from '../../dist/tools/audit-dns.js';

test('DNS policy rejects internal, mapped, transition and reserved addresses', () => {
  for (const ip of ['127.0.0.1','10.0.0.1','169.254.169.254','100.64.0.1','192.168.1.1','0.0.0.0','192.0.2.1','224.0.0.1','::1','fc00::1','fe80::1','::ffff:127.0.0.1','2002:7f00:1::','2001:db8::1']) assert.equal(isPublicAuditAddress(ip), false, ip);
  for (const ip of ['8.8.8.8','1.1.1.1','2606:4700:4700::1111']) assert.equal(isPublicAuditAddress(ip), true, ip);
});

function lookup(fn, options = {}) {
  return new Promise((resolve, reject) => fn('cjrb.net', options, (error, address, family) => error ? reject(error) : resolve({address,family})));
}
test('socket lookup resolves once and returns the same verified address', async () => {
  let calls=0;
  const fn=createSafeLookup(async () => { calls++; return calls===1 ? [{address:'1.1.1.1',family:4}] : [{address:'127.0.0.1',family:4}]; });
  assert.deepEqual(await lookup(fn), {address:'1.1.1.1',family:4});
  assert.equal(calls,1);
  await assert.rejects(lookup(fn), /Non-public DNS/);
});
test('mixed public/private answers and empty answers fail closed', async () => {
  await assert.rejects(lookup(createSafeLookup(async () => [{address:'1.1.1.1',family:4},{address:'10.0.0.1',family:4}])), /Non-public DNS/);
  await assert.rejects(lookup(createSafeLookup(async () => [])), /No DNS/);
});
test('all-address callback contains only the verified answer set', async () => {
  const answers=[{address:'1.1.1.1',family:4},{address:'2606:4700:4700::1111',family:6}];
  assert.deepEqual((await lookup(createSafeLookup(async () => answers),{all:true})).address,answers);
});
