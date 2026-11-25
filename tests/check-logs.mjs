// Real PHP file discovery/rendering without any native pfSense libraries.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { PHP } from '@php-wasm/universal';
import { loadNodeRuntime } from '@php-wasm/node';

const php = new PHP(await loadNodeRuntime('8.5', { emscriptenOptions: { processId: 620 } }));
const lib = new URL('../lib/', import.meta.url);
for (const p of ['/kit/lib','/conf/pf-start/runs/first','/conf/pf-start/runs/second',
  '/conf/pf-start/diagnostics','/conf/pf-start/management','/outside']) php.mkdirTree(p);
for (const name of ['accounts.php','core.php','diagnostics.php','logs.php','management.php','sessions.php','pf-start.php']) {
  php.writeFile('/kit/lib/'+name, fs.readFileSync(new URL(name,lib),'utf8'));
}
const seed = {'actions.jsonl':'{"action":"fixture"}\n',
  'runs/first/audit.json':'{"audit":"first"}\n','runs/second/audit.json':'{"audit":"second"}\n',
  'diagnostics/native-warnings.json':'{"warnings":[]}\n','management/watchdog.log':'watchdog fixture\n',
  'management/pending.json':'{"phase":"enforced","deadline":1}\n','notes.txt':'fixture note\n',
  'garbled.json':'unstructured diagnostic text\n'};
for(const [name,body] of Object.entries(seed))php.writeFile('/conf/pf-start/'+name,body);
php.writeFile('/conf/pf-start/runs/first/config.xml','SECRET CONFIG BACKUP');
php.writeFile('/conf/pf-start/runs/first/master.passwd.reference','SECRET PASSWORD HASH');
php.writeFile('/outside/hidden.log','OUTSIDE LOG');
php.writeFile('/conf/config.xml','UNREADABLE CONFIGURATION FIXTURE');
await php.run({code:`<?php
$i=0;foreach(${JSON.stringify(Object.keys(seed)) .replace(/^/, 'json_decode(\'').replace(/$/, "',true)")}as$p)touch('/conf/pf-start/'.$p,200000+$i++);
symlink('/outside/hidden.log','/conf/pf-start/link.log');symlink('/outside','/conf/pf-start/link-directory');
`});
let checks=0;
function ok(value,label){assert.ok(value,label);checks++;}
async function run(args=['logs','--list'],{interactive=false,input='',extra=''}={}){
  php.writeFile('/input.txt',input);
  const options=Buffer.from(JSON.stringify({args,interactive})).toString('base64');
  let response;
  try{
    response=await php.run({code:`<?php
namespace {if(!function_exists('posix_geteuid')){function posix_geteuid(){return 0;}}
if(!defined('STDERR'))define('STDERR',fopen('php://stderr','w'));
if(!defined('STDIN'))define('STDIN',fopen('/input.txt','r'));
if(!defined('STDOUT'))define('STDOUT',fopen('php://output','w'));
$fixture=json_decode(base64_decode('${options}'),true);$GLOBALS['interactive']=$fixture['interactive'];
$argv=array_merge(['pf-start.php'],$fixture['args']);}
namespace PFStart {function php_uname($kind='a'){return $kind==='s'?'FreeBSD':'amd64';}
function posix_geteuid(){return 0;}function stream_isatty($stream){return $GLOBALS['interactive'];}}
namespace {${extra} require('/kit/lib/pf-start.php');}`});
  }catch(error){response=error.response;if(!response)throw error;}
  return response;
}

let response=await run();
ok(response.exitCode===0&&!response.errors,'logs list succeeds without native libraries or a valid configuration');
let files=JSON.parse(response.text).files;
ok(files.length===Object.keys(seed).length,'all JSON, JSONL, log and text report files are discovered recursively: '+JSON.stringify(files.map(x=>x.path)));
ok(!files.some(x=>/config.xml|master.passwd|link/.test(x.path)),'credential backups and symlink files/directories are excluded');
ok(files.every((x,i)=>i===0||files[i-1].modified>=x.modified),'files appear newest first');
ok(files.every(x=>/^[a-f0-9]{20}$/.test(x.key)),'selection uses stable file keys rather than user-supplied paths');
const firstKeys=files.map(x=>x.key);
response=await run(['logs']);
ok(JSON.stringify(JSON.parse(response.text).files.map(x=>x.key))===JSON.stringify(firstKeys),'redirected logs command lists files without prompting');
const entry=files.find(x=>x.path==='runs/second/audit.json');
response=await run(['logs','--file',entry.key]);
ok(response.exitCode===0&&response.text===seed[entry.path],'selected file streams its exact content when redirected');
for(const args of [['logs','--file','../../outside/hidden.log'],['logs','--list','--file',entry.key],['logs','--unknown']]){
 response=await run(args);
 ok(response.exitCode!==0&&!response.text.includes('OUTSIDE LOG'),'invalid log selection/options fail without exposing other files');
}
ok(Object.entries(seed).every(([p,b])=>php.readFileAsText('/conf/pf-start/'+p)===b),'viewing and listing do not modify report contents');
ok(php.readFileAsText('/conf/config.xml')==='UNREADABLE CONFIGURATION FIXTURE','log viewing never refreshes or repairs native configuration');
ok(php.readFileAsText('/conf/pf-start/management/pending.json')===seed['management/pending.json'],'viewing does not roll back an expired management transaction');
php.writeFile('/conf/pf-start/long.log',Array.from({length:25},(_,i)=>`LINE_${i+1}\n`).join(''));
response=await run();
const long=JSON.parse(response.text).files.find(x=>x.path==='long.log');
response=await run(['logs','--file',long.key],{interactive:true,input:'q\n'});
ok(response.text.includes('LINE_20')&&!response.text.includes('LINE_25')&&response.text.includes('Enter for more'),'fallback viewer pages long logs and q returns');
response=await run(['logs'],{interactive:true,input:'1\n0\n'});
ok(response.exitCode===0&&response.text.includes('Saved logs and reports')&&response.text.includes('Viewing'),'interactive browser selects a file and returns to its list');
for(let i=0;i<17;i++)php.writeFile(`/conf/pf-start/page-${i}.log`,'page fixture\n');
response=await run(['logs'],{interactive:true,input:'n\n999\np\nr\n0\n'});
ok(response.exitCode===0&&response.text.includes('page 2/2')&&response.text.includes('Choose a number')&&response.text.includes('page 1/2'),'browser supports paging, invalid selections, refresh and back');
response=await run(['logs','--list'],{extra:`require('/kit/lib/core.php');require('/kit/lib/logs.php');if(PFStart\\log_label("a\\x1b[31m\\nb")!=="a[31mb")throw new RuntimeException('unsafe label');`});
ok(response.exitCode===0,'terminal control characters are removed from file labels');
response=await run(['logs','--file',entry.key],{extra:"unlink('/conf/pf-start/runs/second/audit.json');"});
ok(response.exitCode!==0&&response.errors.includes('No saved log matches'),'deleted logs produce a useful selection error');
await php.run({code:`<?php rename('/conf/pf-start','/conf/saved-state');`});
response=await run();
ok(response.exitCode===0&&JSON.parse(response.text).files.length===0,'first use with no state directory gives an empty list without creating state');
response=await run(['logs'],{interactive:true,input:'0\n'});
ok(response.exitCode===0&&response.text.includes('Run an audit first'),'empty interactive browser explains how to generate reports');
await php.run({code:`<?php symlink('/conf/saved-state','/conf/pf-start');`});
response=await run();
ok(response.exitCode!==0&&response.errors.includes('symbolic link'),'a replaced state-directory symlink is refused');
console.log(`${checks} log browser checks passed with PHP 8.5 and no native pfSense libraries.`);
process.exit(0);
