export function setToken(t){localStorage.setItem('token',t)}
export function getToken(){return localStorage.getItem('token')||''}
export function clearToken(){localStorage.removeItem('token')}
export async function ensureAuth(){const t=getToken();if(!t){location.href='/login.html';return}try{const r=await fetch('/api/auth/me',{headers:{Authorization:'Bearer '+t}});if(!r.ok)throw 0;const d=await r.json();return d.user}catch(e){clearToken();location.href='/login.html'}}
export async function api(m,u,b){const t=getToken();const o={method:m,headers:{'Content-Type':'application/json'}};if(t)o.headers.Authorization='Bearer '+t;if(b)o.body=JSON.stringify(b);const r=await fetch(u,o);if(r.status===401){clearToken();location.href='/login.html';return}return r}
