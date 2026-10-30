const {chromium}=require(process.env.CDSS_PLAYWRIGHT_MODULE || 'playwright');
const fs=require('node:fs'); const assert=require('node:assert/strict');
const out=process.env.CDSS_E2E_OUTPUT_DIR, base='http://127.0.0.1:5001';
if (!out) throw new Error('Set CDSS_E2E_OUTPUT_DIR to a directory outside the repository.');
let diagnosticPage;
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.CDSS_BROWSER_EXECUTABLE});
 const context=await browser.newContext({viewport:{width:1440,height:1000}});
 const page=await context.newPage(); const errors=[],checks=[],timings={};
 diagnosticPage=page;
 page.on('pageerror',e=>errors.push(e.message)); page.on('console',m=>{if(m.type()==='error'&&!m.text().includes('favicon'))errors.push(m.text())});
 async function visit(path){const t=Date.now();const r=await page.goto(base+path);assert.equal(r.status(),200);timings[path]=Date.now()-t;assert((await page.locator('main').innerText()).length>30);}
 async function screenshot(name){await page.screenshot({path:out+'/'+name+'.png',fullPage:false});}
 const creds=JSON.parse(fs.readFileSync(out+'/browser-disposable-credentials.json','utf8'));
 await visit('/login'); await page.getByLabel('Username',{exact:true}).fill(creds.username);await page.getByLabel('Password',{exact:true}).fill(creds.password);
 await Promise.all([page.waitForURL(base+'/'),page.getByRole('button',{name:'Sign in',exact:true}).click()]);
 assert(await page.getByRole('heading',{name:'Investigate Next',exact:true}).isVisible());
 assert(await page.locator('#next-heading').isVisible());
 assert.equal(await page.locator('meta[http-equiv="refresh"]').count(),0);
 await screenshot('e2e-triage-desktop');checks.push('normal login -> triage -> Investigate Next and reason');
 const contrast=await page.locator('.primary-panel .triage-actions > a').evaluate(el=>{
   const rgb=v=>(v.match(/[\d.]+/g)||[]).slice(0,3).map(Number);
   const lum=values=>values.map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4}).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);
   const a=lum(rgb(getComputedStyle(el).color)),b=lum(rgb(getComputedStyle(el.closest('.primary-panel')).backgroundColor));return(Math.max(a,b)+.05)/(Math.min(a,b)+.05);
 });assert(contrast>=4.5,'Analyst action-link contrast '+contrast.toFixed(2)+' is below 4.5');checks.push('analyst action-link contrast '+contrast.toFixed(2));
 const card=page.locator('.primary-panel .triage-family');assert((await card.innerText()).includes('Initial Alert Priority'));
 const target=await card.locator('form').getAttribute('action');assert(target.match(/^\/alerts\/groups\/\d+\/investigate$/));
 await page.getByRole('link',{name:'Detections',exact:true}).click();
 await page.locator('select[name="priority"]').selectOption('Critical');await page.getByRole('button',{name:'Apply',exact:true}).click();
 assert(new URL(page.url()).searchParams.get('priority')==='Critical');
 await page.locator('.priority-badge').first().waitFor();const priorities=await page.locator('.priority-badge').allTextContents();assert(priorities.length>0&&priorities.every(x=>x.trim()==='CRITICAL'),JSON.stringify(priorities));
 checks.push('detections filters change URL and all rendered priorities match');
 const familyLink=page.getByRole('link',{name:'Compare related detections →',exact:true});
 if(await familyLink.count()){await familyLink.first().click();assert((await page.locator('main').innerText()).includes('Investigate one selection at a time'));checks.push('family -> selected artifact scope');}
 const review=page.getByRole('link',{name:'Review detection →',exact:true});
 if(await review.count()){const groupT=Date.now();await review.first().click();assert((await page.locator('main').innerText()).includes('Occurrence'));timings.group_detail=Date.now()-groupT;}
 await visit('/incidents');checks.push('investigations list renders');
 await visit('/incidents/10923');let text=await page.locator('main').innerText();assert(text.includes('T1 — Limited Evidence'));assert(text.includes('Initial Alert Priority\nCritical'));assert(text.includes('Saved Contextual Risk\nMedium'));checks.push('real T1/Critical distinction rendered');
 await visit('/incidents/11331');text=await page.locator('#evidence-progression').innerText();assert(text.includes('10.10.10.10:8080'));assert(!text.includes('OneDrive'));assert(text.includes('Matching process instance'));await screenshot('e2e-t4-desktop');checks.push('corrected T4 chain, destination, background separation');
 await visit('/');await page.locator('.primary-panel .triage-family form button').click();await page.waitForURL(/\/incidents\/\d+$/);
 const caseUrl=page.url();text=await page.locator('main').innerText();assert(text.includes('Advisory guidance only'));assert(text.includes('Analyst Decision'));
 const assessmentText=await page.locator('#contextual-assessment').innerText();assert(assessmentText.includes('Evidence State'));
 await page.getByLabel('Decision',{exact:true}).selectOption('further_investigation_required');await page.getByLabel('Comment / reason',{exact:true}).fill('Disposable browser verification; no security action executed.');await page.getByRole('button',{name:'Save decision',exact:true}).click();
 assert((await page.locator('#analyst-decision').innerText()).includes('Further Investigation Required'));checks.push('investigate -> evidence assessment -> advisory guidance -> saved analyst decision on disposable DB');
 await visit('/admin/alert-retention');await page.getByLabel('From (UTC)',{exact:true}).fill('2026-10-01T00:00');await page.getByLabel('To (UTC)',{exact:true}).fill('2026-10-28T23:59');
 let t=Date.now();await page.getByRole('button',{name:'Preview',exact:true}).click();await page.getByRole('heading',{name:'Deletion preview',exact:true}).waitFor();timings.retention_post=Date.now()-t;
 assert((await page.locator('main').innerText()).includes('Protected by investigation/audit history'));assert.equal(await page.getByLabel(/I confirm deletion/).isChecked(),false);checks.push('admin retention preview only, purge confirmation untouched');
 await screenshot('e2e-retention-desktop');
 await page.setViewportSize({width:390,height:844});await visit('/');await screenshot('e2e-triage-mobile');
 assert((await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)));await page.getByRole('link',{name:'Detections',exact:true}).press('Tab');assert(await page.evaluate(()=>document.activeElement!==document.body));checks.push('mobile390px no horizontal overflow and keyboard focus');
 await visit('/alerts?q=unmatchable-browser-fixture-query');assert((await page.locator('main').innerText()).includes('No matching'));checks.push('empty state');
 await visit('/alerts?period=custom&from=bad&to=bad');assert((await page.locator('main').innerText()).includes('valid From/To'));checks.push('invalid-filter state');
 await visit('/');await page.clock.install();await page.clock.runFor(3601000);await page.waitForURL(/\/login/);checks.push('browser session-expiry redirect');
 const report={checks,errors,timings,desktop:'1440x1000',mobile:'390x844',caseUrl,scope:'Disposable main-data backup; no live decisions/purges or source queries'};
 fs.writeFileSync(out+'/browser-e2e-results.json',JSON.stringify(report,null,2));assert.equal(errors.length,0,JSON.stringify(errors));console.log(JSON.stringify(report));await browser.close();
})().catch(async e=>{console.error(e.stack);if(diagnosticPage){console.error('PAGE',diagnosticPage.url(),(await diagnosticPage.locator('main').innerText()).slice(0,2200));await diagnosticPage.screenshot({path:out+'/e2e-failure.png'});}process.exit(1)});
