import base64,hashlib,io,json,os,subprocess,sys,tarfile,tempfile,unittest
from pathlib import Path
D=Path(__file__).resolve().parents[1];sys.path.insert(0,str(D/'framework'))
import release,updater,github,broker
OPENSSL=os.environ.get('MAIL_TEST_OPENSSL','openssl')
class ReleaseTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.t=tempfile.TemporaryDirectory();cls.root=Path(cls.t.name);cls.key=cls.root/'key';cls.pub=cls.root/'pub'
  release.openssl_run(OPENSSL,['genpkey','-algorithm','ED25519','-out',cls.key]);release.openssl_run(OPENSSL,['pkey','-in',cls.key,'-pubout','-out',cls.pub])
 @classmethod
 def tearDownClass(cls):cls.t.cleanup()
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.p=Path(self.tmp.name);(self.p/'code.py').write_text('print("fixture")\n',encoding='utf-8');self.rows=[{'source':'code.py','name':'payload/installer.py','sha256':release.sha((self.p/'code.py').read_bytes()),'mode':0o755}]
 def tearDown(self):self.tmp.cleanup()
 def bundle(self):
  m=release.build(self.p,self.rows,'1.2.3',self.p/'bundle.tgz',False);sig=release.sign(m,self.key,OPENSSL);return m,sig
 def test_signed_bundle(self):
  m,sig=self.bundle();manifest,files=release.inspect(self.p/'bundle.tgz',m,sig,self.pub,OPENSSL);self.assertFalse(manifest['install_ready']);self.assertEqual(set(files),{'bundle.json','payload/installer.py'})
 def test_deterministic(self):
  m,_=self.bundle();n=release.build(self.p,self.rows,'1.2.3',self.p/'second.tgz');self.assertEqual(m,n)
 def test_signature_tamper(self):
  m,sig=self.bundle();m['version']='1.2.4'
  with self.assertRaises(release.ReleaseError):release.inspect(self.p/'bundle.tgz',m,sig,self.pub,OPENSSL)
 def test_archive_tamper(self):
  m,sig=self.bundle();p=self.p/'bundle.tgz';p.write_bytes(p.read_bytes()[:-1]+b'x')
  with self.assertRaises(release.ReleaseError):release.inspect(p,m,sig,self.pub,OPENSSL)
 def test_unsafe_paths(self):
  for v in ['/etc/passwd','payload/../../etc/shadow','payload\\code','payload//x','payload/./x','code.py','payload/../x']:
   with self.subTest(v=v),self.assertRaises(release.ReleaseError):release.member(v)
 def test_source_escape(self):
  self.rows[0]['source']='../code.py'
  with self.assertRaises(release.ReleaseError):release.build(self.p,self.rows,'1.0.0',self.p/'out')
 def test_private_extension(self):
  (self.p/'password.key').write_text('fixture');self.rows[0]['source']='password.key'
  with self.assertRaises(release.ReleaseError):release.build(self.p,self.rows,'1.0.0',self.p/'out')
 def test_source_pin(self):
  self.rows[0]['sha256']='0'*64
  with self.assertRaises(release.ReleaseError):release.build(self.p,self.rows,'1.0.0',self.p/'out')
 def test_duplicate(self):
  with self.assertRaises(release.ReleaseError):release.build(self.p,self.rows*2,'1.0.0',self.p/'out')
 def test_versions(self):
  for v in ['main','latest','1.2','01.2.3','1.2.3-rc1','../../1.2.3']:
   with self.subTest(v=v),self.assertRaises(release.ReleaseError):release.version(v)
 def test_upgrade_order(self):
  for v in ['1.0.0','0.9.0']:
   with self.assertRaises(release.ReleaseError):updater.should_apply({'mode':'automatic'},'1.0.0',v)
 def test_modes(self):
  self.assertTrue(updater.should_apply({'mode':'automatic'},'1.0.0','1.0.1'));self.assertFalse(updater.should_apply({'mode':'manual'},'1.0.0','1.0.1'));self.assertTrue(updater.should_apply({'mode':'manual'},'1.0.0','1.0.1',manual=True))
 def test_policy_revision(self):
  self.assertEqual(updater.policy({'revision':2},'automatic',2),{'revision':3,'mode':'automatic'})
  with self.assertRaises(release.ReleaseError):updater.policy({'revision':2},'manual',1)
 def test_repo(self):
  self.assertEqual(github.repo('owner/repo'),'owner/repo')
  for s in ['https://github.com/owner/repo','owner/repo/../../x','/repo','owner/repo?token=x']:
   with self.assertRaises(release.ReleaseError):github.repo(s)
 def test_no_unsigned_url(self):
  with self.assertRaises(release.ReleaseError):github.request('http://127.0.0.1/',1)
 def test_broker_refuses_extra_fields(self):
  with self.assertRaises(release.ReleaseError):broker.operation({'operation':'status','command':'rm'},self.p)
 def test_broker_refuses_unsigned_command(self):
  with self.assertRaises(release.ReleaseError):broker.operation({'operation':'shell'},self.p)
 def test_extract(self):
  m,sig=self.bundle();_,f=release.inspect(self.p/'bundle.tgz',m,sig,self.pub,OPENSSL);release.extract_verified(f,self.p/'stage');self.assertEqual((self.p/'stage/payload/installer.py').read_bytes(),(self.p/'code.py').read_bytes())
 def test_reextract_refused(self):
  with self.assertRaises(release.ReleaseError):release.extract_verified({},self.p)
 def test_bad_signature_encoding(self):
  with self.assertRaises(release.ReleaseError):release.verify_signature({},'invalid!',self.pub,OPENSSL)
 def test_redirect_strips_token(self):
  import urllib.request
  req=urllib.request.Request('https://api.github.com/repos/x/y',headers={'Authorization':'Bearer fixture'})
  new=github.Redirect().redirect_request(req,None,302,'',{},'https://release-assets.githubusercontent.com/a');self.assertNotIn('Authorization',new.headers)
 def test_redirect_refuses_arbitrary_host(self):
  import urllib.request
  with self.assertRaises(release.ReleaseError):github.Redirect().redirect_request(urllib.request.Request('https://api.github.com/a'),None,302,'',{},'https://attacker.invalid/a')
if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReleaseTests));record={'status':'pass'if result.wasSuccessful()else'fail','testsRun':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'platform':sys.platform,'Linux_full_lifecycle_tested':False};(D/'local-tests.json').write_text(json.dumps(record,indent=2),encoding='utf-8');raise SystemExit(not result.wasSuccessful())
