import assert from 'node:assert/strict';
import { DynamoOAuthStore } from '../dist/oauth-dynamodb-store.js';
const items = new Map();
process.env.SEO_MCP_OAUTH_INIT_CLIENT_COUNTER='1';
let scans=0, transactions=0;
const failure = name => Object.assign(new Error(name),{name});
function fakeApi() {
 return {
  table:'registration-test', key:pk=>({pk:{S:pk}}),
  async get(pk){return structuredClone(items.get(pk)??null);},
  async scan(prefix){scans++;return [...items].filter(([k])=>k.startsWith(prefix)).map(([,v])=>structuredClone(v));},
  async put(pk,values){if(items.has(pk))throw failure('ConditionalCheckFailedException');items.set(pk,{pk:{S:pk},...structuredClone(values)});},
  async transaction(actions){
   transactions++;const next=new Map([...items].map(([k,v])=>[k,structuredClone(v)]));
   for(const a of actions){
    if(a.Put){const p=a.Put;if(next.has(p.Item.pk.S))throw failure('TransactionCanceledException');next.set(p.Item.pk.S,structuredClone(p.Item));}
    else if(a.Delete){const p=a.Delete,old=next.get(p.Key.pk.S);if(!old||(old.approvedUntil&&Number(old.approvedUntil.N)>=Number(p.ExpressionAttributeValues[':now'].N)))throw failure('TransactionCanceledException');next.delete(p.Key.pk.S);}
    else if(a.Update){const p=a.Update,k=p.Key.pk.S,old=next.get(k),v=p.ExpressionAttributeValues;
     if(p.ConditionExpression.includes(':max')&&(!old||Number(old.n.N)>=Number(v[':max'].N)))throw failure('TransactionCanceledException');
     if(p.ConditionExpression.includes(':budget')&&old&&Number(old.n.N)>=Number(v[':budget'].N))throw failure('TransactionCanceledException');
     if(p.ConditionExpression.includes(':zero')&&Number(old?.n?.N??0)<=0)throw failure('TransactionCanceledException');
     const n=Number(old?.n?.N??0)+Number(v[':one'].N);next.set(k,{pk:{S:k},n:{N:String(n)},...(v[':ttl']?{ttl:v[':ttl']}: {})});
    }else throw Error('Unsupported transaction');
   }items.clear();for(const [k,v]of next)items.set(k,v);
  },
 };
}
function store(){const s=new DynamoOAuthStore('registration-test','us-east-1');s.api=fakeApi();return s;}
// Seed an existing table close to the declared maximum, then race two instances.
for(let i=0;i<499;i++)items.set('client#old'+i,{pk:{S:'client#old'+i},body:{S:JSON.stringify({clientId:'old'+i,name:null,redirectUris:['https://example.com/cb'],createdAt:new Date().toISOString(),lastUsedAt:null})}});
const a=store(),b=store();
const results=await Promise.allSettled(Array.from({length:25},(_,i)=>(i%2?a:b).registerClient('test',['https://example.com/cb'])));
assert.equal(results.filter(x=>x.status==='fulfilled').length,1,'concurrent registrations cannot exceed 500');
assert.equal([...items.keys()].filter(x=>x.startsWith('client#')).length,500);
const initialScans=scans;
await assert.rejects(a.registerClient('full',['https://example.com/cb']));
assert.equal(scans,initialScans,'full-table scans do not occur after startup initialization');
assert(transactions<=27,'each registration attempts one bounded transaction');
// Fresh table: global per-minute admission budget holds across instances.
items.clear();scans=0;transactions=0;const c=store(),d=store();
const burst=await Promise.allSettled(Array.from({length:30},(_,i)=>(i%2?c:d).registerClient('burst',['https://example.com/cb'])));
assert.equal(burst.filter(x=>x.status==='fulfilled').length,20,'global minute budget enforced transactionally');
// Cleanup is leased across instances and cannot delete a concurrently approved client.
for(const item of items.values())if(item.pk.S.startsWith('client#')){const v=JSON.parse(item.body.S);v.createdAt=new Date(Date.now()-2*86400000).toISOString();item.body.S=JSON.stringify(v);}
const approved=[...items.values()].find(x=>x.pk.S.startsWith('client#'));approved.approvedUntil={N:String(Math.floor(Date.now()/1000)+90*86400)};
const beforeCleanup=scans;
assert.equal(await c.pruneClients(),19);
assert.equal(await d.pruneClients(),0,'hourly lease prevents duplicate scans');
assert.equal(scans-beforeCleanup,2);
assert.equal(await c.countClients(),1,'cleanup and counter decrement are atomic');
assert(items.has(approved.pk.S));
items.get(approved.pk.S).approvedUntil={N:'1'};items.delete([...items.keys()].find(k=>k.startsWith('maintenance#')));
assert.equal(await c.pruneClients(),1,'formerly approved clients become reclaimable after grants expire');
assert.equal(await c.countClients(),0);
// A table without metadata must not bootstrap unless the offline flag is explicit.
items.clear();delete process.env.SEO_MCP_OAUTH_INIT_CLIENT_COUNTER;scans=0;
await assert.rejects(store().prepareRegistration(),/initialized offline/);
assert.equal(scans,0);
console.log('DynamoDB registration concurrency, bounded work and global budget tests passed');
