// Cloudflare Worker: private app behind Cloudflare Access, JSON stored in GitHub.
// REQUIRED: protect the Worker hostname with a Cloudflare Access self-hosted application.
// Also validates the Access JWT, rather than trusting a user-controlled email header.
const json=(data,status=200,extra={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store","x-content-type-options":"nosniff",...extra}});
function b64toBytes(b){const s=atob(b.replace(/-/g,'+').replace(/_/g,'/'));return Uint8Array.from(s,c=>c.charCodeAt(0))}
function bytesToB64(b){let out='';for(let i=0;i<b.length;i+=8192)out+=String.fromCharCode(...b.subarray(i,i+8192));return btoa(out)}
function decode64url(s){return JSON.parse(new TextDecoder().decode(b64toBytes(s)))}
async function identify(req,env){
 const token=req.headers.get('Cf-Access-Jwt-Assertion');if(!token)throw Error('ACCESS_REQUIRED');
 const [h,p,s,...rest]=token.split('.');if(rest.length||!s)throw Error('BAD_JWT');
 const header=decode64url(h),payload=decode64url(p);
 if(header.alg!=='RS256'||!header.kid)throw Error('BAD_ALGORITHM');
 const domain=String(env.ACCESS_TEAM_DOMAIN||'').replace(/\/$/,'');
 if(!domain.startsWith('https://')||payload.iss!==domain||!(Array.isArray(payload.aud)?payload.aud.includes(env.ACCESS_AUD):payload.aud===env.ACCESS_AUD))throw Error('BAD_ISSUER');
 const now=Math.floor(Date.now()/1000);if(!payload.exp||payload.exp<=now||payload.nbf>now+60)throw Error('EXPIRED');
 const certResponse=await fetch(domain+'/cdn-cgi/access/certs',{cf:{cacheTtl:3600,cacheEverything:true}});
 if(!certResponse.ok)throw Error('CERTS_UNAVAILABLE');
 const certs=await certResponse.json();const keyJwk=(certs.keys||[]).find(k=>k.kid===header.kid&&k.kty==='RSA');
 if(!keyJwk)throw Error('UNKNOWN_KEY');
 const key=await crypto.subtle.importKey('jwk',keyJwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
 const good=await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,b64toBytes(s),new TextEncoder().encode(h+'.'+p));
 if(!good)throw Error('BAD_SIGNATURE');
 const email=String(payload.email||'').trim().toLowerCase();if(!email)throw Error('NO_EMAIL');
 return {email,admin:email===String(env.ADMIN_EMAIL||'').trim().toLowerCase()};
}
async function gh(env,path,method='GET',body){
 const repo=String(env.GITHUB_REPO||'');if(!/^[\w.-]+\/[\w.-]+$/.test(repo))throw Error('BAD_REPO');
 const res=await fetch('https://api.github.com/repos/'+repo+'/contents/'+path,{
 method,headers:{'accept':'application/vnd.github+json','authorization':'Bearer '+env.GITHUB_TOKEN,'x-github-api-version':'2022-11-28','user-agent':'albergues-nay-worker','content-type':'application/json'},
 body:body?JSON.stringify(body):undefined});
 const obj=await res.json().catch(()=>({}));
 if(!res.ok)throw Error('GITHUB_'+res.status+': '+(obj.message||'error'));
 return obj;
}
async function readText(env,path){
 const obj=await gh(env,path);if(!obj.content)throw Error('NO_CONTENT');
 const bytes=b64toBytes(obj.content.replace(/\s/g,'').replace(/\+/g,'-').replace(/\//g,'_'));
 return {text:new TextDecoder().decode(bytes),sha:obj.sha};
}
export default {async fetch(req,env){
 let user;try{user=await identify(req,env)}catch(e){return json({error:'Acceso denegado. Se requiere sesión válida de Cloudflare Access.'},401)}
 const u=new URL(req.url),path=u.pathname;
 if(path==='/api/me'&&req.method==='GET')return json(user);
 if(path==='/api/state'&&req.method==='GET'){
   try{const d=await readText(env,'data/albergues.json');return json({registros:JSON.parse(d.text).registros,revision:d.sha})}
   catch(e){return json({error:'No fue posible leer el directorio.'},502)}
 }
 if(path==='/api/state'&&req.method==='PUT'){
   if(!user.admin)return json({error:'Solo administrador'},403);
   if((req.headers.get('content-type')||'').split(';')[0]!=='application/json')return json({error:'Se requiere JSON'},415);
   const origin=req.headers.get('origin');if(origin&&origin!==u.origin)return json({error:'Origen no permitido'},403);
   const raw=await req.text();if(raw.length>1600000)return json({error:'Archivo demasiado grande'},413);
   let body;try{body=JSON.parse(raw)}catch{return json({error:'JSON inválido'},400)}
   if(!Array.isArray(body.registros)||body.registros.length>4000||!body.registros.every(r=>r&&typeof r.id==='string'&&typeof r.nombre==='string'&&typeof r.abierto==='boolean'))return json({error:'Registros inválidos'},400);
   try{
     const curr=await readText(env,'data/albergues.json');
     if(body.revision!==curr.sha)return json({error:'Los datos cambiaron en otra sesión. Recarga antes de volver a guardar.'},409);
     const encoded=bytesToB64(new TextEncoder().encode(JSON.stringify({version:1,actualizado:new Date().toISOString(),actualizado_por:user.email,registros:body.registros},null,2)));
     const out=await gh(env,'data/albergues.json','PUT',{message:'Actualizar aperturas y directorio de albergues',content:encoded,sha:curr.sha,branch:env.GITHUB_BRANCH||'main'});
     return json({ok:true,revision:out.content.sha});
   }catch(e){return json({error:'No fue posible guardar en GitHub.'},502)}
 }
 if(path==='/'||path==='/index.html'){
   try{const app=await readText(env,'secure/app.html');return new Response(app.text,{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer','content-security-policy':"default-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"}})}
   catch{return new Response('Aplicación no disponible',{status:502})}
 }
 return new Response('No encontrado',{status:404});
}};