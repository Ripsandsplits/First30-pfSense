import { PHP } from '@php-wasm/universal';
import { loadNodeRuntime, createNodeFsMountHandler } from '@php-wasm/node';
import fs from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';

const root = fs.mkdtempSync(path.join(tmpdir(),'pf-start-regression-'));
fs.mkdirSync(root, {recursive:true});
for (const d of ['lib','pages','sessions','etc','state']) fs.mkdirSync(root+'/'+d,{recursive:true});
const php = new PHP(await loadNodeRuntime('8.5',{emscriptenOptions:{processId:502}}));
php.mkdirTree(root);
await php.mount(root,createNodeFsMountHandler(root));
for(const name of ['accounts.php','core.php','diagnostics.php','sessions.php','management.php','pf-start.php']) {
 let source=fs.readFileSync(path.resolve(new URL('../lib/',import.meta.url).pathname)+'/'+name,'utf8');
 if(name==='pf-start.php') source=source.split("\ntry {\n    if (php_uname")[0];
 source=source.replaceAll('/conf/pf-start',root+'/state')
  .replaceAll('/conf/config.xml',root+'/config.xml')
  .replaceAll('/etc/master.passwd',root+'/master.passwd')
  .replaceAll('/etc/group',root+'/group')
  .replaceAll('/usr/local/www/*.php',root+'/pages/*.php')
  .replaceAll('/etc/version',root+'/version')
  .replaceAll('/etc/inc/filter.inc',root+'/etc/filter.inc')
  .replaceAll('/etc/inc/service-utils.inc',root+'/etc/service-utils.inc')
  .replaceAll('/etc/rc.php-fpm_restart',root+'/etc/rc.php-fpm_restart')
  .replaceAll('/etc/rc.restart_webgui',root+'/etc/rc.restart_webgui')
  .replaceAll('/usr/sbin/daemon',root+'/etc/daemon');
 if(name==='core.php') source=source.replace('function run_command(', 'function unused_native_run_command(');
 fs.writeFileSync(root+'/lib/'+name,source);
}
for(const name of ['filter.inc','service-utils.inc','rc.php-fpm_restart','rc.restart_webgui','daemon']){
 fs.writeFileSync(root+'/etc/'+name,'<?php // fixture\n');fs.chmodSync(root+'/etc/'+name,0o700);
}
fs.writeFileSync(root+'/version','TEST-PFSENSE\n');
fs.writeFileSync(root+'/pages/priv.php',`<?php
##|+PRIV
##|*IDENT=page-system-usermanager
##|*WARN=standard-warning-root
##|-PRIV
`);
const uid=process.getuid();
fs.writeFileSync(root+'/native.php',`<?php
namespace {
 $fixture=json_decode(file_get_contents('${root}/fixture.json'),true);
 $config=json_decode(file_get_contents('${root}/config.xml'),true);
 $commands=[];
 $pfLive=is_file('${root}/live')?file_get_contents('${root}/live'):'';
 $writes=0;
 $fpm=true;
 function config_get_path($path,$default=null){global $config;$v=$config;foreach(explode('/',$path) as $k){if(!is_array($v)||!array_key_exists($k,$v))return $default;$v=$v[$k];}return $v;}
 function config_set_path($path,$value){global $config;$ref=&$config;foreach(explode('/',$path) as $k){if(!isset($ref[$k]))$ref[$k]=[];$ref=&$ref[$k];}$ref=$value;}
 function config_del_path($path){global $config;$keys=explode('/',$path);$last=array_pop($keys);$ref=&$config;foreach($keys as $k){if(!isset($ref[$k]))return;$ref=&$ref[$k];}unset($ref[$last]);}
 function parse_config($fresh=false){return json_decode(file_get_contents('${root}/config.xml'),true);}
 function write_config($description=''){global $writes,$config;$writes++;file_put_contents('${root}/config.xml',json_encode($config));return true;}
 function local_user_get_groups($user,$all=false){$r=$all?['all']:[];foreach(config_get_path('system/group',[])as$g){if(in_array($user['uid'],$g['member']??[]))$r[]=$g['name'];}return $r;}
 function auth_get_authserver($mode){return ['type'=>$mode==='Remote'?'ldap':'Local Auth'];}
 function phpsession_begin(){session_save_path('${root}/sessions');}
 function phpsession_end($keep){}
 function filter_configure_sync($delete=true){global $pfLive,$fixture;if(!empty($fixture['reload_fail_once'])){unset($fixture['reload_fail_once']);throw new \\RuntimeException('mock reload failure');}$pfLive=implode("\\n",array_column(config_get_path('filter/rule',[]),'descr'));file_put_contents('${root}/live',$pfLive);}
 function get_services(){global $fixture;return $fixture['services'];}
 function get_service_status($entry){global $fixture;return $fixture['running'][$entry['name']]??false;}
 function service_control_restart($name,$extras){global $fixture,$commands;$commands[]=['native-restart',$name,$extras];$fixture['running'][$name]=true;return 'restarted';}
}
namespace PFStart {
 function posix_geteuid(){return ${uid};}
 function posix_kill($pid,$signal){return true;}
 function openlog($a,$b,$c){}
 function syslog($a,$b){}
 function closelog(){}
 function getenv($name){global $fixture;return $fixture['env'][$name]??'';}
 function run_command($args,$interactive=false){
  global $commands,$fixture,$pfLive,$fpm;
  $commands[]=$args;$name=basename($args[0]);
  if($name==='pfctl')return [0,$pfLive,''];
  if($name==='daemon'){file_put_contents($args[array_search('-p',$args)+1],'12345');return [0,'',''];}
  if($name==='pgrep')return [$fpm?0:1,'',''];
  if($name==='pkill'){$fpm=false;return [0,'',''];}
  if($name==='rc.php-fpm_restart'){$fpm=true;return [0,'',''];}
  if($name==='who')return [0,'admin pts/0 team-host\\nother pts/2 other-host\\n',''];
  if($name==='ps')return [0,"10 1 0 pts/0 tcsh\\n20 1 0 pts/2 sh\\n30 1 0 ? sshd\\n",''];
  return [0,'',''];
 }
}
`);
let weak,strong;
const response=await php.run({code:`<?php echo json_encode([password_hash('pfsense',PASSWORD_BCRYPT,['cost'=>4]),password_hash('long strong test password',PASSWORD_BCRYPT,['cost'=>4])]);`});
[weak,strong]=JSON.parse(response.text);
const baselineRules=[{type:'pass',descr:'existing business rule',tracker:1234,source:{any:''},destination:{any:''}}];
let fixture,config,os;
function reset(){
 function clearFiles(directory){ for(const entry of fs.readdirSync(directory,{withFileTypes:true})){ const p=directory+'/'+entry.name; if(entry.isDirectory())clearFiles(p);else fs.unlinkSync(p); } }
 clearFiles(root+'/state');
 fixture={env:{PF_START_TTY:'/dev/pts/0'},services:[{name:'unbound',description:'DNS resolver'},{name:'openvpn',id:1},{name:'openvpn',id:2}],running:{unbound:true,openvpn:true}};
 const rows=[['admin','0',weak,['user-shell-access']],['ops','2001',strong,[]],['shelluser','2002',strong,['user-shell-access']],['delegated','2003',strong,['page-system-usermanager']],['vpnuser','2004',strong,['user-ipsec-xauth-dialin']],['disabledadmin','2005',strong,['page-all']]];
 config={system:{user:rows.map(([name,uid,hash,priv])=>({name,uid,'bcrypt-hash':hash,priv,...(name==='disabledadmin'?{disabled:true}:{})})),group:[{name:'operators',member:['2001'],priv:['page-all']}],webgui:{authmode:'Local Database',protocol:'https'}},interfaces:{lan:{if:'vtnet1',ipaddr:'192.0.2.1',subnet:'24'},wan:{if:'vtnet0',ipaddr:'dhcp'}},filter:{rule:structuredClone(baselineRules)}};
 os=rows.map(([name,uid,hash])=>[name,hash,uid,'65534','','0','0','test','/home/'+name,'/bin/sh']);
 os.push(['root',weak,'0','0','','0','0','root','/root','/bin/sh'],['toor','*','0','0','','0','0','locked','/root','/bin/sh'],['rogue',weak,'0','0','','0','0','rogue','/root','/bin/sh']);
 fs.writeFileSync(root+'/live','existing business rule');
 write();
}
function write(){fs.writeFileSync(root+'/fixture.json',JSON.stringify(fixture));fs.writeFileSync(root+'/config.xml',JSON.stringify(config));fs.writeFileSync(root+'/master.passwd',os.map(r=>r.join(':')).join('\n')+'\n');fs.writeFileSync(root+'/group','wheel:*:0:root,admin\n');}
async function run(code){
 const prefix=`<?php if(!defined('STDERR'))define('STDERR',fopen('php://stderr','w'));if(!defined('STDOUT'))define('STDOUT',fopen('php://stdout','w')); require '${root}/native.php'; require '${root}/lib/pf-start.php';`;
 const suffix=`echo "\\n__RESULT__",json_encode(['writes'=>$writes,'commands'=>$commands]);`;
 let r;try{r=await php.run({code:prefix+code+suffix});}catch(e){if(!e.response)throw e;r=e.response;}
 if(r.errors)throw new Error(r.errors+'\n'+r.text);
 const [output,result]=r.text.split('\n__RESULT__');
 return {output,meta:JSON.parse(result)};
}
let count=0;
function ok(condition,label){assert.ok(condition,label);count++;console.log('PASS',label);}
function expr(code){return run(`echo json_encode(${code});`);}
function thrown(code){return run(`try{${code};echo 'NO_ERROR';}catch(\\Throwable $e){echo 'EXPECTED_ERROR';}`);}
reset();
let r=await expr(`PFStart\\rotation_targets(PFStart\\account_inventory(),[],false)`);
let targets=JSON.parse(r.output).map(x=>x.name);
ok(targets.includes('admin')&&targets.includes('ops'),'direct and inherited administrators selected');
ok(targets.includes('delegated')&&targets.includes('shelluser'),'root GUI and shell accounts selected');
ok(!targets.includes('vpnuser')&&!targets.includes('disabledadmin')&&!targets.includes('toor'),'VPN-only disabled and locked accounts excluded');
ok(targets.includes('rogue'),'unmanaged UID-0 account detected');
r=await expr(`PFStart\\rotation_targets(PFStart\\account_inventory(),[],true)`);
ok(JSON.parse(r.output).map(x=>x.name).join(',')==='admin,rogue','default-only selects known defaults');
r=await expr(`PFStart\\rotation_targets(PFStart\\account_inventory(['vpnuser']),['vpnuser'],false)`);
ok(JSON.parse(r.output).map(x=>x.name).join(',')==='vpnuser','explicit user selection is exact');
r=await thrown(`PFStart\\account_inventory(['missing'])`);ok(r.output==='EXPECTED_ERROR','unknown local account rejected');
r=await expr(`PFStart\\parse_cidr('192.0.2.37/24')`);ok(JSON.parse(r.output).address==='192.0.2.0/24','IPv4 network normalized');
r=await expr(`PFStart\\parse_cidr('2001:db8::123/64')`);ok(JSON.parse(r.output).address==='2001:db8::/64','IPv6 network normalized');
for(const bad of ['0.0.0.0/0','::/0','192.0.2.1/99','not-an-ip']){r=await thrown(`PFStart\\parse_cidr(${JSON.stringify(bad)})`);ok(r.output==='EXPECTED_ERROR','invalid/broad CIDR rejected '+bad);}
r=await expr(`PFStart\\address_in_cidr('192.0.2.37','192.0.2.0/24')`);ok(r.output==='true','IPv4 inclusion works');
r=await expr(`PFStart\\address_in_cidr('2001:db8::1','2001:db8::/64')`);ok(r.output==='true','IPv6 inclusion works');
r=await expr(`PFStart\\address_in_cidr('192.0.3.1','192.0.2.0/24')`);ok(r.output==='false','outside source rejected');
r=await thrown(`PFStart\\options_for(['--aply'],['--apply'=>false])`);ok(r.output==='EXPECTED_ERROR','unknown option rejected');
r=await thrown(`PFStart\\single_option(['--ports'=>['22','443']],'--ports')`);ok(r.output==='EXPECTED_ERROR','ambiguous single option rejected');
const spec={interfaces:['lan'],sources:[{address:'192.0.2.10/32',ipprotocol:'inet',prefix:32}],ports:['22','443'],timeout:180};
const jsphp=x=>`json_decode(${JSON.stringify(JSON.stringify(x))},true)`;
r=await expr(`PFStart\\management_rules(${jsphp(spec)},'abc',true,1000000000)`);
let rules=JSON.parse(r.output);
ok(rules.length===6,'management rule count covers both ports and address families');
ok(rules[0].type==='pass'&&rules[1].type==='block'&&rules[2].ipprotocol==='inet6','allowed sources precede IPv4 and IPv6 blocks');
ok(rules.every(x=>x.floating==='yes'&&x.quick==='yes'&&x.direction==='in'&&x.destination.network==='(self)'&&x.protocol==='tcp'),'management rules are limited to inbound firewall TCP destinations');
r=await expr(`PFStart\\management_rules(${jsphp(spec)},'abc',false,1000000000)`);ok(JSON.parse(r.output).every(x=>x.type==='pass'),'stage contains allow rules only');
r=await thrown(`PFStart\\management_spec(['--interface'=>['missing'],'--allow'=>['192.0.2.10'],'--ports'=>['22']])`);ok(r.output==='EXPECTED_ERROR','unknown interface rejected');
r=await expr(`PFStart\\terminal_targets(PFStart\\terminal_snapshot(),[],true)`);ok(JSON.parse(r.output).join(',')==='pts/2','operator terminal survives others selection');
r=await thrown(`PFStart\\terminal_targets(PFStart\\terminal_snapshot(),['pts/0'],false)`);ok(r.output==='EXPECTED_ERROR','operator terminal cannot be selected');
// Rotation verification catches partial native updates.
r=await expr(`PFStart\\account_fingerprint(PFStart\\account_inventory()['admin'])`);const fingerprint=JSON.parse(r.output);
r=await thrown(`PFStart\\verify_rotation(PFStart\\account_inventory()['admin'],${jsphp(fingerprint)})`);ok(r.output==='EXPECTED_ERROR','unchanged password fails verification');
config.system.user[0]['bcrypt-hash']=strong;os.find(x=>x[0]==='admin')[1]=strong;os.find(x=>x[0]==='root')[1]=strong;write();
r=await run(`PFStart\\verify_rotation(PFStart\\account_inventory()['admin'],${jsphp(fingerprint)});echo 'OK';`);ok(r.output==='OK','synchronized password update accepted');
os.find(x=>x[0]==='root')[1]=weak;write();r=await thrown(`PFStart\\verify_rotation(PFStart\\account_inventory()['admin'],${jsphp(fingerprint)})`);ok(r.output==='EXPECTED_ERROR','root synchronization failure detected');
reset();
const stage={'--interface':['lan'],'--allow':['192.0.2.10/32'],'--ports':['22,443'],'--timeout':['180']};
r=await run(`PFStart\\stage_management(${jsphp(stage)});`);ok(r.meta.writes===0&&!fs.existsSync(root+'/state/management/pending.json'),'management preview has no config or transaction changes');
r=await run(`PFStart\\stage_management(${jsphp({...stage,'--apply':true,'--console-ready':true})});`);
let tx=JSON.parse(fs.readFileSync(root+'/state/management/pending.json'));
ok(tx.phase==='staged'&&r.meta.writes===0,'staging remains runtime-only');
ok(JSON.parse(fs.readFileSync(root+'/config.xml')).filter.rule.length===1,'staging preserves saved business rules');
ok(r.meta.commands.some(x=>path.basename(x[0])==='daemon'),'watchdog armed before trial use');
const token=tx.token;
r=await run(`PFStart\\enforce_management(${jsphp({'--token':[token],'--apply':true,'--access-tested':true})});`);
tx=JSON.parse(fs.readFileSync(root+'/state/management/pending.json'));
ok(tx.phase==='enforced'&&r.meta.writes===0,'enforcement remains runtime-only');
ok(fs.readFileSync(root+'/live','utf8').includes('PFSTART-'+token),'runtime restrictions contain expected labels');
r=await thrown(`PFStart\\require_no_management_trial()`);ok(r.output==='EXPECTED_ERROR','pending trial blocks unrelated mutations');
r=await run(`PFStart\\rollback_management(PFStart\\transaction_for_token('${token}'));`);
ok(r.meta.writes===0&&fs.readFileSync(root+'/live','utf8')==='existing business rule','rollback restores saved rules without replacing configuration');
r=await run(`PFStart\\rollback_management(PFStart\\transaction_for_token('${token}'));`);ok(r.meta.writes===0,'repeated rollback is idempotent');
reset();r=await run(`PFStart\\stage_management(${jsphp({...stage,'--apply':true,'--console-ready':true})});`);tx=JSON.parse(fs.readFileSync(root+'/state/management/pending.json'));
r=await run(`PFStart\\enforce_management(${jsphp({'--token':[tx.token],'--apply':true,'--access-tested':true})});`);
r=await run(`PFStart\\confirm_management(${jsphp({'--token':[tx.token],'--apply':true,'--access-tested':true})});`);
ok(r.meta.writes===1,'confirmation persists tested rules once');
config=JSON.parse(fs.readFileSync(root+'/config.xml'));
ok(config.system.webgui.noantilockout===true,'confirmed LAN restriction handles anti-lockout');
ok(config.filter.rule.some(x=>x.descr==='existing business rule'),'confirmation preserves business rules');
r=await run(`PFStart\\rollback_management(PFStart\\transaction_for_token('${tx.token}'));`);ok(r.meta.writes===0,'old watchdog leaves confirmed rules alone');
reset();r=await run(`PFStart\\stage_management(${jsphp({...stage,'--apply':true,'--console-ready':true})});`);tx=JSON.parse(fs.readFileSync(root+'/state/management/pending.json'));config.system.new_setting='unrelated edit';write();
r=await thrown(`PFStart\\saved_config_unchanged(PFStart\\transaction_for_token('${tx.token}'))`);ok(r.output==='EXPECTED_ERROR','concurrent saved configuration edit detected');
r=await run(`PFStart\\rollback_management(PFStart\\transaction_for_token('${tx.token}'));`);ok(JSON.parse(fs.readFileSync(root+'/config.xml')).system.new_setting==='unrelated edit','rollback preserves unrelated concurrent changes');
reset();fixture.env.SSH_CONNECTION='198.51.100.1 1234 192.0.2.1 22';write();r=await thrown(`PFStart\\operator_allowed(${jsphp(spec)})`);ok(r.output==='EXPECTED_ERROR','SSH operator outside proposed source list rejected');
reset();r=await expr(`PFStart\\services_public(PFStart\\services_inventory())`);const services=JSON.parse(r.output);ok(services.length===3&&services[1].key!==services[2].key,'service keys distinguish OpenVPN instances');
const dnsKey=services.find(x=>x.name==='unbound').key;
r=await run(`PFStart\\restart_service(${jsphp({'--service':[dnsKey]})});`);ok(!r.meta.commands.some(x=>x[0]==='native-restart'),'restart preview does not restart services');
r=await run(`PFStart\\restart_service(${jsphp({'--service':[dnsKey],'--apply':true})});`);ok(r.meta.commands.filter(x=>x[0]==='native-restart').length===1,'restart targets exactly one configured service');
ok(!r.meta.commands.some(x=>path.basename(x[0])==='shutdown'),'service restart does not reboot');
fs.writeFileSync(root+'/sessions/sess_first','first');fs.writeFileSync(root+'/sessions/sess_second','second');fs.writeFileSync(root+'/sessions/unrelated','keep');
r=await expr(`PFStart\\gui_sessions('${root}/sessions')`);let sessions=JSON.parse(r.output);let sessionKey=Object.keys(sessions)[0];
ok(!r.output.includes('sess_first')&&!r.output.includes('sess_second'),'session display conceals cookie IDs');
r=await expr(`PFStart\\revoke_gui_sessions('${root}/sessions',['${sessionKey}'],false)`);ok(JSON.parse(r.output).length===1&&fs.existsSync(root+'/sessions/unrelated'),'selective revocation preserves other files');

// Failure recovery and transaction races.
reset();fixture.reload_fail_once=true;write();
r=await thrown(`PFStart\\stage_management(${jsphp({...stage,'--apply':true,'--console-ready':true})})`);
ok(r.output.includes('EXPECTED_ERROR'),'failed native reload stops staging');
tx=JSON.parse(fs.readFileSync(root+'/state/management/pending.json'));
ok(tx.phase==='rolled-back'&&fs.readFileSync(root+'/live','utf8')==='existing business rule','failed staging reload returns to saved rules');
reset();r=await run(`PFStart\\stage_management(${jsphp({...stage,'--apply':true,'--console-ready':true})});`);
tx=JSON.parse(fs.readFileSync(root+'/state/management/pending.json'));
r=await thrown(`$t=PFStart\\transaction_for_token('${tx.token}');$t['deadline']=time()-1;PFStart\\require_trial_time($t)`);
ok(r.output==='EXPECTED_ERROR','late confirmation cannot commit after expiry');
r=await thrown(`PFStart\\transaction_for_token('00000000000000000000')`);
ok(r.output==='EXPECTED_ERROR','stale or mismatched watchdog token rejected');
r=await run(`$t=PFStart\\transaction_for_token('${tx.token}');$t['phase']='committing';PFStart\\save_json(PFStart\\pending_path(),$t);PFStart\\overlay_management_rules($t,true);write_config('simulate interrupted commit');`);
config=JSON.parse(fs.readFileSync(root+'/config.xml'));config.system.concurrent_setting='preserve this';write();
r=await run(`PFStart\\rollback_management(PFStart\\transaction_for_token('${tx.token}'));`);
config=JSON.parse(fs.readFileSync(root+'/config.xml'));
ok(config.filter.rule.length===1&&!Object.hasOwn(config.system.webgui,'noantilockout'),'interrupted commit removes its rules and restores prior anti-lockout presence');
ok(config.system.concurrent_setting==='preserve this','interrupted-commit recovery preserves unrelated settings');
reset();r=await run(`PFStart\\stage_management(${jsphp({...stage,'--apply':true,'--console-ready':true})});`);
tx=JSON.parse(fs.readFileSync(root+'/state/management/pending.json'));fixture.env.SSH_CONNECTION='192.0.2.10 50000 192.0.2.1 22';write();
r=await run(`PFStart\\enforce_management(${jsphp({'--token':[tx.token],'--apply':true,'--access-tested':true})});`);
r=await thrown(`PFStart\\confirm_management(${jsphp({'--token':[tx.token],'--apply':true,'--access-tested':true})})`);
ok(r.output==='EXPECTED_ERROR','same SSH connection cannot confirm enforcement');
fixture.env.SSH_CONNECTION='192.0.2.10 50001 192.0.2.1 22';write();
r=await run(`PFStart\\confirm_management(${jsphp({'--token':[tx.token],'--apply':true,'--access-tested':true})});`);
ok(r.meta.writes===1,'new allowed SSH connection can confirm');

reset();os.find(x=>x[0]==='rogue')[6]='1';write();
r=await expr(`PFStart\\rotation_targets(PFStart\\account_inventory(),[],false)`);
ok(!JSON.parse(r.output).some(x=>x.name==='rogue'),'expired OS-only administrator is excluded');
r=await expr(`PFStart\\account_fingerprint(PFStart\\account_inventory()['rogue'])`);
ok(JSON.parse(r.output).state[2]==='1','OS account verification includes expiration state');

fs.rmSync(root,{recursive:true,force:true});
console.log(`${count} checks passed with PHP 8.5 and mocked pfSense APIs.`);
process.exit(0);
