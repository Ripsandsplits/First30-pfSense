// Workstation regressions: real PHP, simulated pfSense libraries/host commands.
// Fixtures reproduce API contracts and warning types, not a running firewall.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { PHP } from '@php-wasm/universal';
import { loadNodeRuntime } from '@php-wasm/node';

const lib = new URL('../lib/', import.meta.url);
const php = new PHP(await loadNodeRuntime('8.5', { emscriptenOptions: { processId: 619 } }));
for (const p of ['/kit/lib','/etc/inc','/conf','/tmp','/root','/usr/local/www','/usr/local/lib','/sessions']) php.mkdirTree(p);
for (const name of ['accounts.php','core.php','diagnostics.php','management.php','sessions.php','pf-start.php']) {
  let source = fs.readFileSync(new URL(name, lib), 'utf8');
  if (name === 'core.php') source = source.replace('function run_command(', 'function unused_native_run_command(');
  php.writeFile('/kit/lib/' + name, source);
}
php.writeFile('/etc/version', '2.9.2-API-FIXTURE');
php.writeFile('/etc/master.passwd', 'root:*:0:0::0:0:root:/root:/bin/sh\nadmin:*:0:0::0:0:admin:/root:/bin/sh\n');
php.writeFile('/etc/group', 'wheel:*:0:root,admin\n');
php.writeFile('/etc/inc/globals.inc', '<?php $GLOBALS["bootstrap_arch"]=$ARCH??null; $GLOBALS["bootstrap_gui_flag"]=$do_not_include_config_gui_inc??null;');
const modernLoader = `<?php
function config_read_file($backup=false,$cache=true){
 $GLOBALS['reads'][]=[$backup,$cache];
 if($GLOBALS['profile']==='modern-fail')return false;
 $GLOBALS['config']=json_decode(file_get_contents('/conf/config.xml'),true);return true;
}
`;
php.writeFile('/etc/inc/config.inc', `<?php
if(strpos($GLOBALS['profile'],'legacy')===0){
 $config=json_decode(file_get_contents('/conf/config.xml'),true);
 function parse_config($force=false){
  $GLOBALS['legacy_force']=$force;
  if($GLOBALS['profile']==='legacy-fail')return false;
  $fresh=json_decode(file_get_contents('/conf/config.xml'),true);
  if($GLOBALS['profile']==='legacy-array')return $fresh;
  $GLOBALS['config']=$fresh;return $GLOBALS['profile']==='legacy-null'?null:true;
 }
} else { require_once('/etc/inc/config.lib.inc'); }
require_once('/etc/inc/auth.inc');
`);
php.writeFile('/etc/inc/auth.inc', `<?php
function fixture_index_users(){
 foreach(config_get_path('system/user',[])as$user){$userindex[$user['name']]=$user['uid'];}
 return $userindex;
}
$GLOBALS['indexed_users']=fixture_index_users();
if(!$do_not_include_config_gui_inc)$GLOBALS['gui_loaded']=true;
function phpsession_begin(){ $GLOBALS['session_begins']++; session_start(); }
function phpsession_end($keep){ session_write_close(); }
`);
php.writeFile('/etc/inc/pfsense-utils.inc', '<?php function compile_warning_fixture(){while(true){switch(1){case 1: continue;}break;}}');
php.writeFile('/etc/inc/functions.inc', '<?php require_once("/etc/inc/pfsense-utils.inc");');
php.writeFile('/etc/inc/filter.inc', '<?php // Audit must never apply rules.');
php.writeFile('/etc/inc/service-utils.inc', `<?php
function get_services(){
 if($GLOBALS['profile']==='native-throw')throw new RuntimeException('native inventory failure');
 if($GLOBALS['profile']!=='quiet')for($i=0;$i<2;$i++){$x=[];$unused=$x['ipaddrv6'];}
 return [['name'=>'unbound','description'=>'Resolver']];
}
function get_service_status($s){return true;}
function service_control_restart($name,$args){throw new RuntimeException('Unexpected service restart');}
function fixture_suppressed_warning(){ $x=[]; return @$x['optional']; }
function fixture_native_throw(){ throw new RuntimeException('native exception'); }
`);
php.writeFile('/kit/lib/probe.php', '<?php function kit_warning_fixture(){trigger_error("kit warning remains visible",E_USER_WARNING);}');
php.writeFile('/support.php', String.raw`<?php
namespace {
 if(!function_exists('posix_geteuid')){function posix_geteuid(){return 0;}}
 function config_get_path($path,$default=null){$v=$GLOBALS['config']??null;if($path==='')return is_array($v)?$v:$default;foreach(explode('/',$path)as$k){if(!is_array($v)||!array_key_exists($k,$v))return $default;$v=$v[$k];}return $v;}
 function write_config($why=''){throw new RuntimeException('Unexpected saved configuration write');}
 register_shutdown_function(function(){
  $modes=[];foreach(glob('/conf/pf-start/runs/*/*.json')as$p)$modes[$p]=fileperms($p)&0777;
  $sessions=[];foreach(glob('/sessions/sess_*')as$p)$sessions[basename($p)]=file_get_contents($p);
  file_put_contents('/outcome.json',json_encode([
   'reads'=>$GLOBALS['reads'],'legacy_force'=>$GLOBALS['legacy_force']??null,
   'indexed_users'=>$GLOBALS['indexed_users']??null,'config'=>$GLOBALS['config']??null,
   'arch'=>$GLOBALS['bootstrap_arch']??null,'gui_flag'=>$GLOBALS['bootstrap_gui_flag']??null,
   'gui_loaded'=>$GLOBALS['gui_loaded']??false,'commands'=>$GLOBALS['commands'],
   'session_begins'=>$GLOBALS['session_begins'],'session_status'=>session_status(),
   'sessions'=>$sessions,'audits'=>glob('/conf/pf-start/runs/*/audit.json'),'modes'=>$modes
  ]));
 });
}
namespace PFStart {
 function php_uname($kind='a'){return $kind==='s'?'FreeBSD':'amd64';}
 function posix_geteuid(){return 0;}
 function openlog(...$args){}
 function syslog(...$args){}
 function closelog(){}
 function getenv($name){return $GLOBALS['env'][$name]??'';}
 function run_command($args,$interactive=false){
  $GLOBALS['commands'][]=$args;
  if(basename($args[0])==='who')return [0,"admin ttyv0 console\n",''];
  if(basename($args[0])==='ps')return [0,"10 1 0 v0 sh\n",''];
  return [0,'mock host output',''];
 }
}
`);
const disk = {system:{user:[{name:'admin',uid:'0','bcrypt-hash':'*',priv:['page-all']},
  {name:'worker',uid:'2001','bcrypt-hash':'*'},{name:'observer',uid:'2002','bcrypt-hash':'*'}],
  group:[{name:'admins',priv:['page-all']},{name:'operators',member:['2001'],priv:['page-all']},
    {name:'all',priv:['user-shell-access']}],webgui:{protocol:'https'}},
  interfaces:{lan:{if:'hn1',ipaddr:'192.168.50.1',subnet:'24'}},filter:{rule:[]}};
const diskBytes = JSON.stringify(disk);
let count = 0;
function ok(value, label) { assert.ok(value, label); count++; }
async function run({profile='modern',args=['audit'],code=null,fpm='[nginx]\n',savePath='/sessions',tempEnv='',handler='files'}={}) {
  await php.run({code:`<?php function clear_fixture_tree($p){if(!is_dir($p))return;foreach(scandir($p)as$x){if($x==='.'||$x==='..')continue;$n=$p.'/'.$x;if(is_dir($n)){clear_fixture_tree($n);rmdir($n);}else unlink($n);}}clear_fixture_tree('/conf/pf-start');clear_fixture_tree('/sessions');`});
  php.writeFile('/conf/config.xml', diskBytes);
  php.writeFile('/sessions/sess_fixture', 'fixture browser session bytes');
  // Seed before unlinking so consecutive absent-file scenarios are repeatable.
  php.writeFile('/usr/local/lib/php-fpm.conf',fpm ?? '');
  if(fpm===null)php.unlink('/usr/local/lib/php-fpm.conf');
  php.writeFile('/etc/inc/config.lib.inc',modernLoader);
  if(profile.startsWith('legacy'))php.unlink('/etc/inc/config.lib.inc');
  const settings=JSON.stringify({profile,args,savePath,tempEnv,handler});
  let response;
  try {
    response = await php.run({code:`<?php
ini_set('display_errors','stderr');ini_set('output_buffering','0');ini_set('session.save_path',json_decode('${JSON.stringify(savePath)}'));
$settings=json_decode('${settings}',true);ini_set('session.save_handler',$settings['handler']);
if(!defined('STDERR'))define('STDERR',fopen('php://stderr','w'));
$GLOBALS['profile']=$settings['profile'];$GLOBALS['env']=['TMPDIR'=>$settings['tempEnv']];
$GLOBALS['reads']=[];$GLOBALS['commands']=[];$GLOBALS['session_begins']=0;
require('/support.php');$argv=array_merge(['pf-start.php'],$settings['args']);
${code ?? "require('/kit/lib/pf-start.php');"}`});
  } catch(error) { response=error.response; if(!response)throw error; }
  const meta=JSON.parse(php.readFileAsText('/outcome.json'));
  const report=meta.audits.length?JSON.parse(php.readFileAsText(meta.audits[0])):null;
  return {response,meta,report,output:response.text+'\n'+response.errors};
}

let r = await run();
ok(r.response.exitCode===0 && r.report, 'whole audit completes on the modern boolean-returning loader');
ok(r.meta.reads.length===2 && r.meta.reads.every(x=>x[0]===false&&x[1]===false), 'disk configuration loads before auth and refreshes without recovery/cache');
ok(r.meta.indexed_users.worker==='2001' && !r.output.includes('userindex'), 'native auth indexing sees loaded users');
ok(r.meta.arch==='amd64' && r.meta.gui_flag===true && !r.meta.gui_loaded, 'bootstrap preserves native globals and avoids GUI includes');
ok(r.meta.session_begins===0 && r.meta.session_status===1 && !r.output.includes('session_start'), 'audit never starts a PHP browser session after output');
ok(JSON.stringify(r.meta.sessions)===JSON.stringify({sess_fixture:'fixture browser session bytes'}), 'audit preserves existing sessions and creates none');
ok(php.readFileAsText('/conf/config.xml')===diskBytes && JSON.stringify(r.meta.config)===diskBytes, 'audit leaves saved and in-memory fixture configuration unchanged');
ok(r.report.accounts.worker.groups.includes('operators') && r.report.accounts.worker.privileges.includes('page-all'), 'saved group membership grants inherited privileges');
ok(JSON.stringify(r.report.accounts.observer.groups)===JSON.stringify(['all']) && r.report.accounts.observer.privileges.includes('user-shell-access'), 'absent member lists are safe and the virtual all group applies');
ok(!r.output.includes('Undefined array key') && !r.output.includes('targeting switch'), 'native runtime and compile warnings do not flood the terminal');
ok(r.report.native_warnings.occurrences===3 && r.report.native_warnings.unique_warnings===2, 'native warnings are counted and repeated occurrences aggregate');
const details=JSON.parse(php.readFileAsText(r.report.native_warnings.details_file));
ok(details.warnings.some(x=>x.file==='/etc/inc/service-utils.inc'&&x.occurrences===2&&x.context==='services'&&x.line>0), 'private diagnostics retain source, context, line and counts');
ok(details.warnings.some(x=>x.message.includes('targeting switch')), 'actual PHP compile warnings remain available for review');
ok(Object.values(r.meta.modes).every(x=>x===0o600), 'audit and native-warning evidence are owner-readable only');
ok(r.report.native_inventory_note.includes('Review') && r.output.includes('Review affected inventory'), 'affected inventory is explicitly marked for review');
ok(!r.meta.commands.some(x=>/restart|pkill|shutdown/.test(x[0])), 'audit does not restart services, terminate users or reboot');

for(const profile of ['legacy-array','legacy-bool','legacy-null']){
 r=await run({profile});
 ok(r.response.exitCode===0&&r.report&&r.meta.legacy_force===true, profile+' loader remains supported');
}
for(const profile of ['modern-fail','legacy-fail']){
 r=await run({profile});
 ok(r.response.exitCode!==0&&!r.report&&r.output.includes('ERROR:'), profile+' stops without an audit or repair');
}
r=await run({profile:'native-throw'});
ok(r.response.exitCode===0&&r.report.service_warning==='native inventory failure', 'native service exceptions produce an explicit incomplete-inventory warning');

for(const [label,options]of [
 ['missing native FPM config',{fpm:null}],
 ['FPM includes',{fpm:'include=/custom/*.conf\n'}],
 ['FPM session path override',{fpm:'php_admin_value[session.save_path] = /other\n'}],
 ['FPM session handler override',{fpm:'php_value[session.save_handler] = redis\n'}],
 ['FPM temp-directory override',{fpm:'php_value[sys_temp_dir] = /other\n'}],
 ['nested session layout',{savePath:'2;/sessions'}],
 ['ambiguous CLI TMPDIR',{savePath:'',tempEnv:'/other'}]
]){
 r=await run({...options,args:['gui-revoke','--all','--apply']});
 ok(r.response.exitCode!==0&&Object.keys(r.meta.sessions).length===1&&!r.meta.commands.some(x=>/pkill|restart/.test(x[0])), label+' prevents revocation before any disruption');
}
r=await run({savePath:''});
ok(r.response.exitCode===0&&!r.report.gui_session_warning&&r.meta.session_begins===0, 'default temporary session storage is inspected without session_start');
r=await run({fpm:'php_value[session.save_path] = /other\n'});
ok(r.response.exitCode===0&&r.report.gui_session_warning.includes('overrides'), 'ambiguous session storage is recorded without discarding the audit');

const helperSetup=`require('/kit/lib/core.php');require('/kit/lib/diagnostics.php');require('/etc/inc/service-utils.inc');require('/kit/lib/probe.php');error_reporting(E_ALL);`;
r=await run({code:helperSetup+`PFStart\\native_call('test',function(){fixture_suppressed_warning();kit_warning_fixture();});echo json_encode(PFStart\\native_warning_summary());`});
ok(r.output.includes('kit warning remains visible') && r.response.text.includes('"occurrences":0'), 'suppressed native warnings stay suppressed and kit warnings stay visible');
r=await run({code:helperSetup+`$restored=0;set_error_handler(function()use(&$restored){$restored++;return true;});try{PFStart\\native_call('test',function(){fixture_native_throw();});}catch(Throwable $e){echo $e->getMessage();}trigger_error('restoration probe',E_USER_WARNING);restore_error_handler();echo ' restored='.$restored;`});
ok(r.response.text==='native exception restored=1', 'native exceptions propagate and the prior error handler is restored');
const sessionSource=fs.readFileSync(new URL('sessions.php',lib),'utf8');
ok(!sessionSource.includes('phpsession_begin(')&&!sessionSource.includes('session_start('), 'session inventory contains no session-start helper call');
console.log(`${count} CLI checks passed with PHP 8.5 and simulated pfSense APIs.`);
process.exit(0);
