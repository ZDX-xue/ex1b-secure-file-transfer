'use strict';
const $ = id => document.getElementById(id);
const actions = {
  connect: '建立连接', disconnect: '关闭连接', handshake: '验证证书',
  put_begin: '开始上传', put_finish: '上传校验', get_begin: '开始下载',
  get_finish: '下载校验', admission: '接入控制', frame: '报文检查', limit: '资源控制'
};
let active = null;
let busy = false;
let changing = false;

function bytes(n) {
  if (n >= 1048576) return (n / 1048576).toFixed(n % 1048576 ? 1 : 0) + ' MiB';
  if (n >= 1024) return (n / 1024).toFixed(n % 1024 ? 1 : 0) + ' KiB';
  return n + ' B';
}
function rows(values, map) {
  return values.map(value => {
    const tr = document.createElement('tr');
    for (const text of map(value)) {
      const td = document.createElement('td');
      td.textContent = text;
      tr.append(td);
    }
    return tr;
  });
}
function message(text) {
  $('notice').textContent = text;
  $('notice').hidden = !text;
}
function userElement(user) {
  const row = document.createElement('div');
  row.className = 'user';
  const names = document.createElement('div');
  const label = document.createElement('div');
  label.className = 'identity';
  label.textContent = user.id + ' · ' + user.role;
  const quota = document.createElement('div');
  quota.className = 'quota';
  quota.textContent = '空间配额 ' + bytes(user.quota);
  names.append(label, quota);
  const rate = document.createElement('span');
  rate.className = 'rate';
  rate.textContent = bytes(user.rate) + '/s';
  row.append(names, rate);
  return row;
}
function render(state) {
  active = state;
  $('address').textContent = state.address ? '传输地址 ' + state.address : '正在等待服务端启动';
  $('accepting').textContent = state.accepting ? '接受连接' : '暂停接入';
  $('admission').disabled = changing;
  $('admission').textContent = state.accepting ? '暂停新连接' : '恢复接入';
  $('sessions-count').textContent = state.sessions.length + ' / ' + state.capacity;
  $('accounts-count').textContent = state.users.length;
  const sessions = [...state.sessions].sort((a, b) => a.id.localeCompare(b.id));
  $('sessions').replaceChildren(...rows(sessions, s => [s.id, s.user, s.peer, bytes(s.received), bytes(s.sent), s.requests]));
  $('sessions-empty').hidden = sessions.length > 0;
  $('users').replaceChildren(...state.users.map(userElement));
  const events = [...state.events].reverse().slice(0, 32);
  $('events').replaceChildren(...rows(events, e => [
    new Date(e.time).toLocaleTimeString('zh-CN', {hour12: false}),
    e.user || '—', e.session || '—', actions[e.action] || e.action, e.name || '—',
    e.status + (e.offset ? ' · 偏移 ' + bytes(e.offset) : '')
  ]));
  $('events-empty').hidden = events.length > 0;
}
async function refresh() {
  if (busy) return;
  busy = true;
  try {
    const response = await fetch('/api/state', {cache: 'no-store'});
    if (!response.ok) throw new Error('无法读取当前服务状态');
    render(await response.json());
    message('');
  } catch (e) {
    message(e.message === 'Failed to fetch' ? '与本机管理页的连接已断开' : e.message);
    $('admission').disabled = true;
  } finally {
    busy = false;
  }
}
$('refresh').addEventListener('click', refresh);
$('admission').addEventListener('click', async () => {
  if (!active || changing) return;
  changing = true;
  $('admission').disabled = true;
  try {
    const response = await fetch('/api/admission', {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-Ex1b-Token': active.token},
      body: JSON.stringify({accepting: !active.accepting})
    });
    if (!response.ok) throw new Error('接入设置未保存');
  } catch (e) { message(e.message); }
  changing = false;
  await refresh();
});
refresh();
setInterval(refresh, 1200);
