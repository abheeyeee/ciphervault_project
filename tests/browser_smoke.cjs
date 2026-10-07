const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
(async()=>{
 const temp=await fs.mkdtemp(path.join(os.tmpdir(),'ciphervault-qa-'));
 const base=process.env.CIPHERVAULT_URL||'http://127.0.0.1:8000';
 const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||undefined,args:['--no-sandbox']});
 const context=await browser.newContext({acceptDownloads:true});
 const page=await context.newPage();
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 page.on('dialog',d=>d.accept());
 await page.goto(base);
 assert(await page.getByRole('link',{name:'Use in your browser'}).count());
 await page.goto(base+'/app');
 // From this point, actual vault operations must send no HTTP requests,
 // including failed requests or attempts blocked by the vault's CSP.
 const vaultNetwork=[];
 page.on('request',r=>{if(/^https?:/.test(r.url()))vaultNetwork.push(r.url());});
 await page.evaluate(()=>{
  window.vaultPolicyViolations=[];
  document.addEventListener('securitypolicyviolation',event=>window.vaultPolicyViolations.push(event.violatedDirective));
 });
 const pass='correct horse battery staple test';
 await page.locator('#master').fill(pass);await page.locator('#confirm').fill(pass);await page.locator('#ack').check();await page.locator('#gate-submit').click();await page.locator('#workspace').waitFor({state:'visible'});
 await page.locator('#add-button').click();await page.locator('#entry-name').fill('Email <test>');await page.locator('#entry-user').fill('me@example.com');await page.locator('#entry-url').fill('https://example.com');await page.locator('#entry-pass').fill('secret-unique-password');await page.locator('#entry-notes').fill('private note');await page.locator('#save-entry').click();await page.locator('#entry-dialog').waitFor({state:'hidden'});
 assert.equal(await page.locator('.entry h3').textContent(),'Email <test>');
 const encrypted=await page.evaluate(()=>localStorage.getItem('ciphervault.browser.v1'));
 for(const plain of ['secret-unique-password','private note','me@example.com',pass])assert(!encrypted.includes(plain));
 await page.getByRole('button',{name:'Edit',exact:true}).click();await page.locator('#entry-name').fill('Updated email');await page.locator('#save-entry').click();await page.locator('#entry-dialog').waitFor({state:'hidden'});
 await page.locator('#search').fill('nonsense');assert.equal(await page.locator('.entry').count(),0);await page.locator('#search').fill('updated');assert.equal(await page.locator('.entry').count(),1);await page.locator('#search').fill('');
 const backup=page.waitForEvent('download');await page.locator('#backup-button').click();const download=await backup;const backupPath=path.join(temp,'test.ciphervault');await download.saveAs(backupPath);
 await page.locator('#header-lock').click();await page.locator('#master').fill('wrong password');await page.locator('#gate-submit').click();await page.waitForFunction(()=>document.getElementById('gate-error').textContent.includes('Incorrect'));assert(await page.locator('#workspace').isHidden());await page.locator('#master').fill(pass);await page.locator('#gate-submit').click();await page.locator('#workspace').waitFor({state:'visible'});assert.equal(await page.locator('.entry h3').textContent(),'Updated email');
 await page.locator('#change-button').click();await page.locator('#current-master').fill(pass);await page.locator('#new-master').fill(pass+' new');await page.locator('#new-confirm').fill(pass+' new');await page.locator('#change-submit').click();await page.locator('#change-dialog').waitFor({state:'hidden'});await page.locator('#header-lock').click();await page.locator('#master').fill(pass);await page.locator('#gate-submit').click();await page.waitForFunction(()=>document.getElementById('gate-error').textContent.includes('Incorrect'));await page.locator('#master').fill(pass+' new');await page.locator('#gate-submit').click();await page.locator('#workspace').waitFor({state:'visible'});
 await page.getByRole('button',{name:'Delete',exact:true}).click();await page.waitForFunction(()=>document.getElementById('entry-count').textContent.startsWith('0'));
 await page.locator('#header-lock').click();await page.locator('#import-file').setInputFiles(backupPath);await page.locator('#master').fill(pass);await page.locator('#gate-submit').click();await page.locator('#workspace').waitFor({state:'visible'});assert.equal(await page.locator('.entry h3').textContent(),'Updated email');
 await page.locator('#generator-button').click();const generated=await page.locator('#generated').textContent();assert.equal(generated.length,20);assert(/[a-z]/.test(generated)&&/[A-Z]/.test(generated)&&/[0-9]/.test(generated));await page.locator('[data-close="generator-dialog"]').click();

 await page.setViewportSize({width:390,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
 // A failed write must not change the existing encrypted vault or visible entries.
 const savedBeforeFailure=await page.evaluate(()=>localStorage.getItem('ciphervault.browser.v1'));
 await page.evaluate(()=>{window.originalSetItem=Storage.prototype.setItem;Storage.prototype.setItem=function(){throw new DOMException('full','QuotaExceededError');};});
 await page.locator('#add-button').click();await page.locator('#entry-name').fill('Should not save');await page.locator('#entry-pass').fill('synthetic password');await page.locator('#save-entry').click();await page.waitForFunction(()=>document.getElementById('entry-error').textContent.includes('not saved'));
 assert.equal(await page.evaluate(()=>localStorage.getItem('ciphervault.browser.v1')),savedBeforeFailure);assert.equal(await page.locator('.entry').count(),1);
 await page.evaluate(()=>{Storage.prototype.setItem=window.originalSetItem;});await page.locator('[data-close="entry-dialog"]').click();
 // Advancing the browser clock exercises the actual inactivity timer.
 await page.clock.install();await page.clock.fastForward(6*60*1000);await page.locator('#welcome').waitFor({state:'visible'});assert.equal(await page.locator('.entry').count(),0);assert.equal(await page.locator('#entry-pass').inputValue(),'');
 const damaged=JSON.parse(await fs.readFile(backupPath,'utf8'));damaged.ciphertext=(damaged.ciphertext[0]==='A'?'B':'A')+damaged.ciphertext.slice(1);
 const damagedPath=path.join(temp,'damaged.ciphervault');await fs.writeFile(damagedPath,JSON.stringify(damaged));await page.locator('#import-file').setInputFiles(damagedPath);await page.locator('#master').fill(pass);await page.locator('#gate-submit').click();await page.waitForFunction(()=>document.getElementById('gate-error').textContent.includes('damaged'));assert.equal(await page.evaluate(()=>localStorage.getItem('ciphervault.browser.v1')),savedBeforeFailure);
 assert.deepEqual(vaultNetwork,[]);
 assert.deepEqual(await page.evaluate(()=>window.vaultPolicyViolations),[]);
 const offlineResponse=await context.request.get(base+'/download');assert(offlineResponse.headers()['content-disposition'].includes('CipherVault.html'));const offlinePath=path.join(temp,'CipherVault.html');await fs.writeFile(offlinePath,await offlineResponse.body());
 const offline=await context.newPage();const network=[];offline.on('request',r=>{if(/^https?:/.test(r.url()))network.push(r.url());});offline.on('pageerror',e=>errors.push(e.message));offline.on('dialog',d=>d.accept());await context.setOffline(true);await offline.goto('file://'+offlinePath);await offline.locator('#import-file').setInputFiles(backupPath);await offline.locator('#master').fill(pass);await offline.locator('#gate-submit').click();await offline.locator('#workspace').waitFor({state:'visible'});assert.equal(await offline.locator('.entry h3').textContent(),'Updated email');assert.deepEqual(network,[]);assert.deepEqual(errors,[]);
 console.log('PASS: create, encrypted persistence, CRUD/search, lock, wrong password, change password, backup/import, password generator, mobile layout, storage failure rollback, auto-lock, tampered backup rejection, offline file import with no network requests');
 await browser.close();
 await fs.rm(temp,{recursive:true,force:true});
})().catch(e=>{console.error(e);process.exit(1)});
