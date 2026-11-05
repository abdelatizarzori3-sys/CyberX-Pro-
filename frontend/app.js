const $ = (s) => document.querySelector(s);
let token = localStorage.getItem('cyberx_token');
let registering = false;
const api = async (path, options = {}) => {
  const response = await fetch(`/api/v1${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(options.headers || {}) }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || 'حدث خطأ غير متوقع');
  return body;
};
const showError = (id, message) => { $(id).textContent = message || ''; };
const toast = (message) => { const el = $('#toast'); el.textContent = message; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 3800); };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function dateField(date) { const d = new Date(date); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0,16); }
function setMode(reg) { registering = reg; $('#register-tab').classList.toggle('active',reg); $('#login-tab').classList.toggle('active',!reg); $('#org-field').classList.toggle('hidden',!reg); $('#auth-submit').firstChild.textContent = reg ? 'إنشاء المؤسسة ' : 'دخول آمن '; $('input[name="organization_name"]').required = reg; $('input[name="password"]').autocomplete = reg ? 'new-password' : 'current-password'; showError('#auth-error',''); }
$('#login-tab').addEventListener('click', () => setMode(false));
$('#register-tab').addEventListener('click', () => setMode(true));
$('#auth-form').addEventListener('submit', async e => { e.preventDefault(); const f = new FormData(e.currentTarget); const payload = {email:f.get('email'),password:f.get('password')}; if (registering) { payload.organization_name = f.get('organization_name'); try { const r = await api('/auth/register',{method:'POST',body:JSON.stringify(payload)}); token = r.access_token; localStorage.setItem('cyberx_token',token); await enterApp(); } catch(err) { showError('#auth-error',err.message); } } else { try { const r = await api('/auth/login',{method:'POST',body:JSON.stringify(payload)}); token = r.access_token; localStorage.setItem('cyberx_token',token); await enterApp(); } catch(err) { showError('#auth-error',err.message); } } });
async function enterApp() { const user = await api('/me'); $('#auth-view').classList.add('hidden'); $('#app-view').classList.remove('hidden'); $('#org-name').textContent = user.organization_name; await refresh(); }
function renderList(id, rows, empty, render) { const el = $(id); el.innerHTML = rows.length ? rows.map(render).join('') : `<div class="empty">${empty}</div>`; }
async function refresh() { const [assets, auths, scans, audit] = await Promise.all([api('/assets'),api('/authorizations'),api('/scans'),api('/audit-logs')]);
  $('#asset-count').textContent = assets.length; $('#auth-count').textContent = auths.filter(a => !a.revoked_at && new Date(a.starts_at) <= new Date() && new Date(a.expires_at) > new Date()).length; $('#scan-count').textContent = scans.length;
  const options = assets.map(a=>`<option value="${esc(a.id)}">${esc(a.name)} — ${esc(a.identifier)}</option>`).join(''); $('#auth-asset').innerHTML = `<option value="">اختر أصلاً</option>${options}`; $('#scan-asset').innerHTML = `<option value="">اختر أصلاً</option>${options}`;
  renderList('#assets-list',assets,'لا توجد أصول بعد.',a=>`<div class="row"><div><strong>${esc(a.name)}</strong><small>${esc(a.identifier)} · ${esc(a.asset_type)}</small></div><span class="badge">مسجل</span></div>`);
  renderList('#authorizations-list',auths,'لا توجد تفويضات بعد.',a=>{ const start=new Date(a.starts_at), end=new Date(a.expires_at), now=new Date(); const state=a.revoked_at?'ملغي':end<=now?'منتهي':start>now?'لم يبدأ بعد':'سارٍ'; const canRevoke=!a.revoked_at&&end>now; return `<div class="row auth-row"><div><strong>${esc(a.asset_name)}</strong><small>${esc(state)} · ينتهي ${end.toLocaleString('ar')}</small></div>${canRevoke?`<button class="secondary compact" type="button" data-revoke-id="${esc(a.id)}">إلغاء</button>`:`<span class="badge">${esc(state)}</span>`}</div>`;});
  renderList('#scans-list',scans,'لا توجد طلبات بعد.',s=>`<div class="row"><div><strong>${esc(s.asset_name)}</strong><small>طلب محلي · ${new Date(s.created_at).toLocaleString('ar')}</small></div><span class="badge">مسجل</span></div>`);
  renderList('#audit-list',audit,'لا توجد أحداث بعد.',a=>`<div class="row"><div><strong>${esc(a.action)}</strong><small>${new Date(a.created_at).toLocaleString('ar')}</small></div></div>`);
}
$('#asset-form').addEventListener('submit', async e => { e.preventDefault(); const f = new FormData(e.currentTarget); try { await api('/assets',{method:'POST',body:JSON.stringify(Object.fromEntries(f))}); e.currentTarget.reset(); await refresh(); toast('تمت إضافة الأصل إلى مساحة مؤسستك.'); } catch(err) { toast(err.message); } });
$('#authorization-form').addEventListener('submit', async e => { e.preventDefault(); const f = new FormData(e.currentTarget); try { await api('/authorizations',{method:'POST',body:JSON.stringify({asset_id:f.get('asset_id'),scope_note:f.get('scope_note'),starts_at:new Date(f.get('starts_at')).toISOString(),expires_at:new Date(f.get('expires_at')).toISOString(),attested:f.get('attested') === 'on'})}); e.currentTarget.reset(); await refresh(); toast('تم تسجيل التفويض. يبقى التحقق القانوني من مستند التفويض مسؤولية المؤسسة.'); } catch(err) { toast(err.message); } });
$('#scan-form').addEventListener('submit', async e => { e.preventDefault(); const f = new FormData(e.currentTarget); try { const r = await api('/scans',{method:'POST',body:JSON.stringify({asset_id:f.get('asset_id')})}); await refresh(); toast(r.message); } catch(err) { toast(err.message); } });
$('#authorizations-list').addEventListener('click', async e => { const button=e.target.closest('[data-revoke-id]'); if (!button || !confirm('هل تريد إلغاء هذا التفويض؟ لن تُقبل طلبات جديدة باستخدامه.')) return; button.disabled=true; try { await api(`/authorizations/${encodeURIComponent(button.dataset.revokeId)}/revoke`,{method:'POST'}); await refresh(); toast('تم إلغاء التفويض وتسجيل الحدث في سجل التدقيق.'); } catch(err) { button.disabled=false; toast(err.message); } });
$('#logout').addEventListener('click', async () => { try { await api('/auth/logout',{method:'POST'}); } catch {} localStorage.removeItem('cyberx_token'); token = null; $('#app-view').classList.add('hidden'); $('#auth-view').classList.remove('hidden'); });
$('#health').textContent = 'الخدمة جاهزة';
if (token) enterApp().catch(() => { localStorage.removeItem('cyberx_token'); token = null; });
$('#authorization-form [name="starts_at"]').value = dateField(new Date());
$('#authorization-form [name="expires_at"]').value = dateField(new Date(Date.now()+86400000));
