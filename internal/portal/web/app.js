"use strict";

const $ = (id) => document.getElementById(id);
const roleName = {normal: "普通用户", vip: "VIP", admin: "管理员"};
const roleRate = {normal: 256 * 1024, vip: 1024 * 1024};
const routes = {
  files: ["文件与传输", "在一条加密会话中管理文件、并行传输和断点续传。"],
  sharing: ["用户互传", "通过服务端给已注册账号发送消息或文件。"],
  monitor: ["服务监控", "查看收发速率、历史流量和通过双向验证的传输会话。"],
  accounts: ["账号管理", "查看注册身份与带宽等级，也可停用、重置密码或删除账号。"],
  audit: ["操作记录", "核对服务端记录的会话、文件与管理操作。"],
  settings: ["账号设置", "查看账户信息、身份验证详情和更新密码。"],
};
const stateNames = {running: "传输中", pausing: "暂停中", paused: "已暂停", done: "校验通过", failed: "失败"};
const active = new Set(["running", "pausing", "paused"]);
const eventNames = {
  connect: "建立连接", disconnect: "关闭连接", handshake: "验证证书",
  put_begin: "开始上传", put_finish: "上传校验", get_begin: "开始下载",
  get_finish: "下载校验", admission: "接入控制", frame: "报文检查", limit: "资源控制",
  share_send: "用户互传", share: "用户互传", share_download: "接收文件", account: "账号状态",
};
const number = new Intl.NumberFormat("zh-CN", {maximumFractionDigits: 1});
const utf8 = new TextEncoder();
const taskNodes = new Map();
let user = null;
let csrf = "";
let route = "files";
let revision = 0;
let polling;
let taskState = [];
let peopleState = [];
let connected = false;
let linkSession = "";
let linkRate = 0;
let filter = "all";
let mailbox = "inbox";
let fileKey = "";
let inboxKey = "";
let accountKey = "";
let lastSharePoll = 0;
let previousTraffic = null;
const historyRanges = {"5m": ["近 5 分钟", 300000], "15m": ["近 15 分钟", 900000], "1h": ["近 1 小时", 3600000], "24h": ["近 24 小时", 86400000]};
let historyRange = "15m";
let historyData = null;
let historyPollTime = 0;
let historyRequest = 0;
let historyPending = false;
let selectedSample = null;
let chartScale = null;
let monitorSessions = [];
let sessionFilter = "all";
let accepting = true;
let staging = 0;
let uploads = [];
let managedAccount = null;
let accountActionTrigger = null;
let entry = {role: "main", name: ""};

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}

function bytes(value) {
  const units = ["B", "KiB", "MiB", "GiB"];
  let amount = Math.max(0, Number(value) || 0);
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit++;
  }
  return number.format(amount) + " " + units[unit];
}

function stamp(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleTimeString("zh-CN", {hour12: false});
}

function notice(text, kind = "note", target = "notice") {
  $(target).textContent = text;
  $(target).dataset.kind = kind;
  $(target).hidden = !text;
}

function markLink(value, text) {
  $("global-state").dataset.state = value;
  $("global-state").textContent = text;
}

class RequestError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(path, options = {}) {
  const {method = "GET", data} = options;
  const headers = {"Accept": "application/json"};
  let body;
  if (method !== "GET" && csrf) headers["X-CSRF-Token"] = csrf;
  if (data instanceof FormData) {
    body = data;
  } else if (data !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(data);
  }
  const response = await fetch(path, {method, body, headers, cache: "no-store", credentials: "same-origin"});
  const value = response.status === 204 ? {} : await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new RequestError(value.error || "请求失败（" + response.status + "）", response.status);
  }
  return value;
}

function post(path, data = {}) {
  return request(path, {method: "POST", data});
}

function showAuthHeading() {
  const wantsRegister = !$("register-form").hidden;
  const isAdmin = entry.role === "admin";
  $("auth-title").textContent = wantsRegister ? "创建账号" : (isAdmin ? "管理员登录" : "登录工作台");
  $("auth-subtitle").textContent = wantsRegister
    ? "注册普通用户或 VIP 账号，获得独立的文件空间。"
    : (isAdmin ? "请使用管理员账号进入服务监控和账号管理。" : "使用账号进入你的文件与传输空间。");
}

function authMode(wantsRegister) {
  wantsRegister = wantsRegister && entry.role !== "admin";
  $("choose-login").setAttribute("aria-pressed", String(!wantsRegister));
  $("choose-register").setAttribute("aria-pressed", String(wantsRegister));
  $("login-form").hidden = wantsRegister;
  $("register-form").hidden = !wantsRegister;
  if (entry.role === "admin") $("login-name").value = "admin";
  showAuthHeading();
  notice("", "note", "auth-notice");
}

function entryLink(candidate) {
  if ((candidate?.role !== "admin" && candidate?.role !== "user") ||
      typeof candidate.name !== "string" || typeof candidate.origin !== "string") return null;
  let url;
  try {
    url = new URL(candidate.origin);
  } catch {
    return null;
  }
  if (url.protocol !== window.location.protocol || url.hostname !== window.location.hostname ||
      url.origin === window.location.origin || url.pathname !== "/" ||
      url.username || url.password || url.search || url.hash) return null;
  const link = node("a", candidate.name);
  link.href = url.origin;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  const arrow = node("span", "↗");
  arrow.setAttribute("aria-hidden", "true");
  link.append(arrow);
  return link;
}

function showEntry(data) {
  if (!["main", "admin", "user"].includes(data?.role) || typeof data.name !== "string") return;
  entry = {role: data.role, name: data.name};
  $("auth-entry").textContent = entry.name;
  $("auth-entry").hidden = !entry.name;
  const isAdmin = entry.role === "admin";
  $("auth-toggle").hidden = isAdmin;
  $("login-name").readOnly = isAdmin;
  if (isAdmin) {
    $("choose-login").setAttribute("aria-pressed", "true");
    $("choose-register").setAttribute("aria-pressed", "false");
    $("login-form").hidden = false;
    $("register-form").hidden = true;
    $("login-name").value = "admin";
  }
  showAuthHeading();
  const links = entry.role === "main" && Array.isArray(data.entries) ? data.entries.map(entryLink).filter(Boolean) : [];
  $("entry-links").replaceChildren(...links);
  $("entry-switcher").hidden = links.length === 0;
  $("workspace-entry-links").replaceChildren(...links.map((link) => link.cloneNode(true)));
  $("workspace-entry-switcher").hidden = links.length === 0;
  showSideRole();
}

function showSideRole() {
  if (!user) return;
  $("side-role").textContent = [roleName[user.role] || user.role, entry.role !== "main" ? entry.name : ""].filter(Boolean).join(" · ");
}

function clearViews() {
  if ($("manage-account").open) $("manage-account").close();
  taskState = [];
  peopleState = [];
  uploads = [];
  fileKey = "";
  inboxKey = "";
  accountKey = "";
  lastSharePoll = 0;
  connected = false;
  linkSession = "";
  linkRate = 0;
  filter = "all";
  mailbox = "inbox";
  previousTraffic = null;
  historyData = null;
  historyPollTime = 0;
  historyRequest++;
  historyPending = false;
  selectedSample = null;
  monitorSessions = [];
  sessionFilter = "all";
  updateSessionFilter();
  renderHistory();
  taskNodes.clear();
  for (const id of ["files", "tasks", "inbox", "admin-sessions", "admin-users", "admin-events", "monitor-events"]) {
    $(id).replaceChildren();
  }
  replaceOptions($("recipients"), "选择接收人", []);
  replaceOptions($("send-files"), "仅发送文字消息", []);
  $("send-form").reset();
  updateMessageLength();
  for (const button of document.querySelectorAll("[data-filter]")) {
    button.setAttribute("aria-pressed", String(button.dataset.filter === "all"));
  }
  for (const button of document.querySelectorAll("[data-mailbox]")) {
    button.setAttribute("aria-pressed", String(button.dataset.mailbox === "inbox"));
  }
}

function showAuth(message = "", kind = "note") {
  revision++;
  user = null;
  csrf = "";
  clearViews();
  $("auth").hidden = false;
  $("workspace").hidden = true;
  authMode(false);
  notice(message, kind, "auth-notice");
}

function openWorkspace(data) {
  if (!data?.user?.username || !data.csrf) throw new Error("服务端未返回完整登录状态");
  revision++;
  clearViews();
  user = data.user;
  csrf = data.csrf;
  $("auth").hidden = true;
  $("workspace").hidden = false;
  $("side-user").textContent = user.username;
  showSideRole();
  $("side-avatar").textContent = user.username.slice(0, 1).toUpperCase();
  $("setting-user").textContent = user.username;
  $("setting-role").textContent = roleName[user.role] || user.role;
  $("setting-enabled").textContent = user.enabled === false ? "停用" : "启用";
  $("setting-rate-row").hidden = user.role === "admin";
  $("certificate-card").hidden = user.role === "admin";
  $("setting-rate").textContent = roleRate[user.role] ? bytes(roleRate[user.role]) + "/s" : "—";
  markLink("connecting", "正在读取状态");
  for (const link of document.querySelectorAll("[data-scope]")) {
    link.hidden = link.dataset.scope !== (user.role === "admin" ? "admin" : "member");
  }
  showRoute(user.role === "admin" ? "monitor" : "files");
}

function showRoute(next) {
  if (!user || !routes[next]) return;
  route = next;
  const [title, description] = routes[route];
  $("route-name").textContent = title;
  $("route-description").textContent = description;
  $("route-name").tabIndex = -1;
  for (const section of document.querySelectorAll("[data-view]")) section.hidden = section.dataset.view !== route;
  for (const link of document.querySelectorAll("[data-route]")) {
    if (link.dataset.route === route) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  notice("");
  if (route === "monitor") {
    window.requestAnimationFrame(drawChart);
    refreshHistory();
  }
  if (route === "sharing") lastSharePoll = 0;
  refresh();
}

function formHandler(id, handle, target = "notice") {
  $(id).addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    if (button.disabled) return;
    button.disabled = true;
    try {
      await handle(Object.fromEntries(new FormData(form)), form);
    } catch (error) {
      showProblem(error, target);
    } finally {
      button.disabled = false;
    }
  });
}

function showProblem(error, target = "notice") {
  if (user && error.status === 401) {
    showAuth("登录已失效，请重新登录。", "error");
    return;
  }
  notice(error.message || "请求失败，请稍后重试。", "error", target);
}

function action(label, handle, className = "secondary compact") {
  const button = node("button", label, className);
  button.type = "button";
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await handle();
    } catch (error) {
      showProblem(error);
    } finally {
      button.disabled = false;
    }
  });
  return button;
}

function cell(content) {
  const el = node("td");
  if (content instanceof Node) el.append(content);
  else el.textContent = content ?? "—";
  return el;
}

function tableRow(...values) {
  const row = node("tr");
  row.append(...values.map(cell));
  return row;
}

function replaceOptions(select, placeholder, data) {
  const previous = select.value;
  const options = data.map(({value, label}) => new Option(label, value));
  const current = [...select.options].map((item) => [item.value, item.label]);
  const wanted = [["", placeholder], ...options.map((item) => [item.value, item.label])];
  if (JSON.stringify(current) === JSON.stringify(wanted)) return;
  select.replaceChildren(new Option(placeholder, ""), ...options);
  if (options.some((item) => item.value === previous)) select.value = previous;
}

function renderConnection(status, problem) {
  connected = Boolean(status) && !problem;
  markLink(connected ? "online" : problem ? "offline" : "connecting", connected ? "传输会话在线" : problem ? "传输连接异常" : "正在连接");
  linkSession = status?.session || "";
  linkRate = status?.rate || 0;
  $("link-session").textContent = linkSession || "—";
  $("link-rate").textContent = status?.rate ? bytes(status.rate) + "/s" : "—";
  if (status?.rate) $("setting-rate").textContent = bytes(status.rate) + "/s";
  $("link-tls").textContent = status?.tls || "—";
  $("setting-session").textContent = linkSession || "—";
  $("setting-client-fp").textContent = status?.client_fingerprint || "等待传输连接";
  $("setting-server-fp").textContent = status?.server_fingerprint || "等待传输连接";
  $("upload").disabled = !connected;
  const previousConnection = $("notice").dataset.kind === "connection";
  if (problem && ($("notice").hidden || previousConnection)) notice(problem, "connection");
  if (connected && previousConnection) notice("");
}

async function requestDownload(name, shareID) {
  const selection = {name};
  if (shareID) selection.share_id = shareID;
  await post("/api/download", selection);
  notice("已加入下载队列。");
  refresh();
}

function renderFiles(files) {
  const key = JSON.stringify([connected, files]);
  if (key === fileKey) return;
  fileKey = key;
  $("file-count").textContent = files.length + " 个文件";
  $("files-empty").hidden = files.length > 0;
  $("files").replaceChildren(...files.map((file) => {
    const name = node("div");
    const title = node("b", file.name, "file-title");
    title.title = file.name;
    name.append(title);
    if (file.sha256) {
      const digest = node("small", "SHA-256 " + file.sha256.slice(0, 12) + "…", "mono digest");
      digest.title = file.sha256;
      name.append(digest);
    }
    const actions = node("div", undefined, "cell-actions");
    const share = action("发送", async () => {
      showRoute("sharing");
      $("send-files").value = file.name;
      $("recipients").focus();
    }, "ghost compact");
    const download = action("下载", () => requestDownload(file.name));
    download.disabled = !connected;
    share.disabled = !connected;
    actions.append(share, download);
    return tableRow(name, bytes(file.size), actions);
  }));
  replaceOptions($("send-files"), "仅发送文字消息", files.map((file) => ({value: file.name, label: file.name})));
}

function taskRow(task) {
  let row = taskNodes.get(task.id);
  if (!row) {
    const item = node("li", undefined, "task");
    const icon = node("span", task.direction === "upload" ? "↑" : "↓", "task-icon");
    icon.dataset.kind = task.direction;
    icon.title = task.direction === "upload" ? "上传" : "下载";
    const body = node("div");
    const top = node("div", undefined, "task-head");
    const summary = node("div");
    const name = node("b", task.name, "task-name");
    const status = node("small", undefined, "task-state");
    const buttons = node("div", undefined, "task-actions");
    const progress = node("progress");
    progress.max = 100;
    progress.setAttribute("aria-label", task.name + " 的传输进度");
    const measure = node("small");
    const detail = node("small", undefined, "task-detail mono");
    summary.append(name, status);
    top.append(summary, buttons);
    body.append(top, progress, measure, detail);
    item.append(icon, body);
    row = {item, status, buttons, progress, measure, detail, actionKey: ""};
    taskNodes.set(task.id, row);
  }
  row.item.dataset.state = task.state;
  row.status.textContent = stateNames[task.state] || task.state;
  row.progress.value = task.state === "done" ? 100 : task.total ? Math.min(100, 100 * task.done / task.total) : 0;
  row.measure.textContent = bytes(task.done) + " / " + bytes(task.total) + (task.rate ? " · " + bytes(task.rate) + "/s" : "");
  const detail = [];
  if (task.resumed_at > 0) detail.push("从 " + bytes(task.resumed_at) + " 续传");
  if (task.state === "done" && task.sha256) detail.push("SHA-256 " + task.sha256.slice(0, 12) + "…");
  if (task.error) detail.push(task.error);
  row.detail.textContent = detail.join(" · ");
  row.detail.title = task.sha256 || "";
  const key = task.state + "/" + Boolean(task.saved);
  if (row.actionKey !== key) {
    row.actionKey = key;
    row.buttons.replaceChildren();
    if (task.state === "running") {
      row.buttons.append(action("暂停", async () => {
        await post("/api/tasks/" + task.id + "/pause");
        refresh();
      }));
    }
    if (task.state === "paused") {
      row.buttons.append(action("继续", async () => {
        await post("/api/tasks/" + task.id + "/resume");
        refresh();
      }));
    }
    if (task.state === "done" && task.saved) {
      const link = node("a", "另存", "secondary compact");
      link.href = "/api/files/" + task.id;
      link.download = task.name;
      row.buttons.append(link);
    }
  }
  return row.item;
}

function renderTasks(tasks) {
  taskState = tasks;
  const activeIDs = new Set(tasks.map((task) => task.id));
  for (const id of taskNodes.keys()) if (!activeIDs.has(id)) taskNodes.delete(id);
  $("running-count").textContent = tasks.filter((task) => task.state === "running").length;
  const rows = tasks.filter((task) => filter === "all" || (filter === "active" ? active.has(task.state) : task.state === "done")).map(taskRow);
  const children = $("tasks").children;
  if (rows.length !== children.length || rows.some((row, index) => row !== children[index])) {
    $("tasks").replaceChildren(...rows);
  }
  $("tasks-empty").hidden = rows.length > 0;
  $("tasks-empty").textContent = filter === "done" ? "暂无已完成的任务。" : filter === "active" ? "暂无进行中的任务。" : "暂无传输任务。";
}

function renderInbox(data, box) {
  const key = JSON.stringify([box, data]);
  if (key === inboxKey) return;
  inboxKey = key;
  $("inbox-count").textContent = data.length + " 条消息";
  $("inbox-empty").textContent = box === "inbox" ? "其他用户发来的消息和文件会显示在这里。" : "你发送的消息和文件会显示在这里。";
  $("inbox-empty").hidden = data.length > 0;
  $("inbox").replaceChildren(...data.map((item) => {
    const row = node("li", undefined, "inbox-row");
    const meta = node("div", undefined, "inbox-head");
    const label = box === "inbox" ? item.sender + " 发来" + (item.name ? "文件" : "消息") : "发送给 " + item.recipient;
    meta.append(node("b", label), node("small", stamp(item.time)));
    row.append(meta);
    if (item.message) row.append(node("p", item.message));
    if (item.name) {
      const file = node("div", undefined, "inbox-file");
      const details = node("div");
      details.append(node("strong", item.name), node("small", bytes(item.size)));
      file.append(details);
      if (box === "inbox") {
        file.append(action("接收文件", async () => {
          await requestDownload(item.name, item.id);
          showRoute("files");
          notice("已加入下载队列。");
        }));
      }
      row.append(file);
    }
    return row;
  }));
}

async function refreshShare(current) {
  lastSharePoll = Date.now();
  const box = mailbox;
  const [people, messages] = await Promise.all([request("/api/people"), request("/api/" + box)]);
  if (current !== revision) return;
  peopleState = people || [];
  replaceOptions($("recipients"), "选择接收人", peopleState.map((person) => ({
    value: person.username, label: person.username + " · " + (roleName[person.role] || person.role),
  })));
  renderShareLimit();
  if (box === mailbox) renderInbox(messages || [], box);
}

function renderShareLimit() {
  const recipient = peopleState.find((person) => person.username === $("recipients").value);
  const recipientRate = roleRate[recipient?.role];
  const rate = recipientRate && linkRate ? Math.min(recipientRate, linkRate) : 0;
  $("share-limit").textContent = rate
    ? "此方向文件接收上限 " + bytes(rate) + "/s，按双方较低档位计算。"
    : "文件接收带宽受发送方和接收方共同限制。";
}

function updateMessageLength() {
  const message = $("send-message");
  const size = utf8.encode(message.value).length;
  $("message-length").textContent = size + " / 512 字节";
  message.setCustomValidity(size > 512 ? "留言不能超过 512 字节。" : "");
}

const chartColors = {input: "#177d69", output: "#426eb0"};
const axisTime = new Intl.DateTimeFormat("zh-CN", {hour: "2-digit", minute: "2-digit", hourCycle: "h23"});
const axisDate = new Intl.DateTimeFormat("zh-CN", {month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hourCycle: "h23"});

function rate(value) {
  return value === null || value === undefined ? "—" : bytes(value) + "/s";
}

function chartCeiling(points) {
  const highest = Math.max(1024, ...points.flatMap((point) => [point.input, point.output]));
  const unit = 2 ** Math.floor(Math.log2(highest / 4));
  return 4 * unit * Math.ceil(highest / (4 * unit));
}

function chartGroups(points, step) {
  const groups = [];
  for (const point of points) {
    const last = groups.at(-1);
    if (!last || point.time_ms - last.at(-1).time_ms > step * 1.5) groups.push([point]);
    else last.push(point);
  }
  return groups;
}

function drawChart() {
  const canvas = $("traffic-chart");
  if (route !== "monitor" || $("workspace").hidden) return;
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  if (!width || !height) return;
  const dpi = window.devicePixelRatio || 1;
  canvas.width = Math.round(width * dpi);
  canvas.height = Math.round(height * dpi);
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.scale(dpi, dpi);
  const points = historyData?.points || [];
  const end = historyData?.end_ms || Date.now();
  const start = historyData?.start_ms || end - historyRanges[historyRange][1];
  const max = chartCeiling(points);
  const top = 12;
  const bottom = height - 29;
  ctx.font = "11px ui-sans-serif, sans-serif";
  const axisLabels = Array.from({length: 5}, (_, index) => rate(index * max / 4));
  const left = Math.ceil(Math.max(...axisLabels.map((label) => ctx.measureText(label).width)) + 12);
  const right = width - 8;
  const x = (time) => left + (right - left) * (time - start) / (end - start);
  const y = (value) => bottom - (bottom - top) * value / max;
  chartScale = {left, right, top, bottom, start, end};

  if (historyData?.since_ms > start) {
    ctx.fillStyle = "#f4f7f8";
    const covered = x(historyData.since_ms);
    ctx.fillRect(left, top, Math.min(right, covered) - left, bottom - top);
  }
  ctx.fillStyle = "#647982";
  ctx.strokeStyle = "#e6edf0";
  ctx.textAlign = "right";
  for (let i = 0; i <= 4; i++) {
    const value = i * max / 4;
    const row = y(value);
    ctx.beginPath();
    ctx.moveTo(left, row + 0.5);
    ctx.lineTo(right, row + 0.5);
    ctx.stroke();
    ctx.fillText(axisLabels[i], left - 8, row + 4);
  }
  const ticks = width < 400 ? 3 : 5;
  const labels = historyRange === "24h" && width >= 510 ? axisDate : axisTime;
  for (let i = 0; i <= ticks; i++) {
    const time = start + (end - start) * i / ticks;
    const at = x(time);
    ctx.textAlign = i === 0 ? "left" : (i === ticks ? "right" : "center");
    ctx.fillText(labels.format(time), at, height - 7);
  }

  const groups = chartGroups(points, historyData?.step_ms || 5000);
  ctx.save();
  ctx.beginPath();
  ctx.rect(left, top - 3, right - left, bottom - top + 6);
  ctx.clip();
  for (const [direction, color] of Object.entries(chartColors)) {
    const gradient = ctx.createLinearGradient(0, top, 0, bottom);
    gradient.addColorStop(0, color + "36");
    gradient.addColorStop(1, color + "03");
    for (const group of groups) {
      if (group.length === 1) {
        ctx.beginPath();
        ctx.arc(x(group[0].time_ms), y(group[0][direction]), 2.5, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();
        continue;
      }
      ctx.beginPath();
      for (const [i, point] of group.entries()) {
        const args = [x(point.time_ms), y(point[direction])];
        if (i === 0) ctx.moveTo(...args);
        else ctx.lineTo(...args);
      }
      ctx.lineWidth = 2;
      ctx.lineJoin = "round";
      ctx.strokeStyle = color;
      ctx.stroke();
      ctx.lineTo(x(group.at(-1).time_ms), bottom);
      ctx.lineTo(x(group[0].time_ms), bottom);
      ctx.closePath();
      ctx.fillStyle = gradient;
      ctx.fill();
    }
  }
  const selected = points.find((point) => point.time_ms === selectedSample);
  if (selected) {
    const at = x(selected.time_ms);
    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(at, top);
    ctx.lineTo(at, bottom);
    ctx.strokeStyle = "#687d88";
    ctx.lineWidth = 1;
    ctx.stroke();
    ctx.setLineDash([]);
    for (const [direction, color] of Object.entries(chartColors)) {
      ctx.beginPath();
      ctx.arc(at, y(selected[direction]), 4, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = "#fff";
      ctx.stroke();
    }
  }
  ctx.restore();
  const tooltip = $("chart-tooltip");
  tooltip.hidden = !selected;
  if (selected) {
    tooltip.dataset.side = x(selected.time_ms) > (right + left) / 2 ? "left" : "right";
    $("chart-point-time").textContent = axisDate.format(selected.time_ms) + (historyData.step_ms < 60000 ? ":" + new Date(selected.time_ms).getSeconds().toString().padStart(2, "0") : "");
    $("chart-point-input").textContent = "接收 " + rate(selected.input);
    $("chart-point-output").textContent = "发送 " + rate(selected.output);
  }
}

function selectSample(point, announce = false) {
  const time = point?.time_ms ?? null;
  if (selectedSample !== time) {
    selectedSample = time;
    drawChart();
  }
  if (announce) $("chart-announcement").textContent = point
    ? [axisDate.format(time), stamp(time), "接收 " + rate(point.input), "发送 " + rate(point.output)].join("，")
    : "";
}

function chartPointer(event) {
  const points = historyData?.points;
  if (!chartScale || !points?.length) return;
  const bounds = event.currentTarget.getBoundingClientRect();
  const {left, right, top, bottom, start, end} = chartScale;
  const px = event.clientX - bounds.left;
  const py = event.clientY - bounds.top;
  if (px < left - 2 || px > right + 2 || py < top - 5 || py > bottom + 5) return selectSample(null);
  const time = start + (end - start) * (px - left) / (right - left);
  const point = points.reduce((a, b) => Math.abs(b.time_ms - time) < Math.abs(a.time_ms - time) ? b : a);
  selectSample(Math.abs(point.time_ms - time) <= historyData.step_ms ? point : null);
}

function chartKeyboard(event) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End", "Escape"].includes(event.key)) return;
  const points = historyData?.points || [];
  if (!points.length) return;
  if (event.key !== "Escape") event.preventDefault();
  const current = points.findIndex((point) => point.time_ms === selectedSample);
  const last = points.length - 1;
  switch (event.key) {
    case "ArrowLeft": selectSample(points[current < 0 ? last : Math.max(0, current - 1)], true); break;
    case "ArrowRight": selectSample(points[Math.min(last, current + 1)], true); break;
    case "Home": selectSample(points[0], true); break;
    case "End": selectSample(points[last], true); break;
    default: selectSample(null, true);
  }
}

function renderHistory(problem = "") {
  const data = historyData;
  const measured = Boolean(data?.points?.length);
  $("stat-window").textContent = historyRanges[historyRange][0];
  $("history-received").textContent = measured ? bytes(data.totals?.received) : "—";
  $("history-sent").textContent = measured ? bytes(data.totals?.sent) : "—";
  $("history-input-avg").textContent = measured ? rate(data.average?.input) : "—";
  $("history-output-avg").textContent = measured ? rate(data.average?.output) : "—";
  $("history-input-peak").textContent = measured ? rate(data.peaks?.input) : "—";
  $("history-output-peak").textContent = measured ? rate(data.peaks?.output) : "—";
  $("history-online-peak").textContent = measured ? (data.peaks?.online ?? "—") : "—";
  $("chart-empty").hidden = measured;
  $("chart-empty").textContent = problem || (data ? "等待服务端完成首次采样" : "正在读取流量历史");
  $("chart-last").textContent = measured ? "最近采样 " + stamp(data.points.at(-1).time_ms) : "";
  $("chart-coverage").textContent = measured && data.since_ms ? "可用记录始于 " + axisDate.format(data.since_ms) : "等待服务端采样";
  const step = data?.step_ms;
  $("chart-resolution").textContent = step ? (step >= 60000 ? step / 60000 + " 分钟" : step / 1000 + " 秒") + "均值" : "";
  drawChart();
}

async function refreshHistory(force = false) {
  if (user?.role !== "admin" || route !== "monitor" ||
      (!force && (historyPending || Date.now() - historyPollTime < 4800))) return;
  const current = revision;
  const key = historyRange;
  const sent = ++historyRequest;
  historyPollTime = Date.now();
  historyPending = true;
  try {
    const data = await request("/api/admin/history?range=" + encodeURIComponent(key));
    if (sent !== historyRequest || current !== revision || key !== historyRange) return;
    historyData = data;
    renderHistory();
  } catch (error) {
    if (sent !== historyRequest || current !== revision) return;
    if (error.status === 401) showAuth("登录已失效，请重新登录。", "error");
    else renderHistory("历史暂不可用");
  } finally {
    if (sent === historyRequest) historyPending = false;
  }
}

function updateTraffic(data) {
  const {incoming = 0, outgoing = 0, received = 0, sent = 0, shared = 0} = data || {};
  $("admin-incoming").textContent = "处理中 " + incoming;
  $("admin-received").textContent = "累计 " + bytes(received);
  $("admin-outgoing").textContent = "处理中 " + outgoing;
  $("admin-sent").textContent = "累计 " + bytes(sent);
  $("admin-shared").textContent = shared;
  const time = performance.now();
  if (!previousTraffic || received < previousTraffic.received || sent < previousTraffic.sent) {
    previousTraffic = {received, sent, time};
    $("admin-input-rate").textContent = "—";
    $("admin-output-rate").textContent = "—";
  } else if (time - previousTraffic.time >= 900) {
    const seconds = (time - previousTraffic.time) / 1000;
    const input = Math.max(0, (received - previousTraffic.received) / seconds);
    const output = Math.max(0, (sent - previousTraffic.sent) / seconds);
    previousTraffic = {received, sent, time};
    $("admin-input-rate").textContent = rate(input);
    $("admin-output-rate").textContent = rate(output);
  }
}

function transferActive(session) {
  return (session.incoming || 0) + (session.outgoing || 0) > 0;
}

function duration(since) {
  const seconds = Math.floor((Date.now() - new Date(since).getTime()) / 1000);
  if (!since || !Number.isFinite(seconds) || seconds < 0) return "—";
  if (seconds < 60) return seconds + " 秒";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return minutes + " 分 " + seconds % 60 + " 秒";
  return Math.floor(minutes / 60) + " 小时 " + minutes % 60 + " 分";
}

function updateSessionFilter() {
  for (const button of document.querySelectorAll("[data-session-filter]")) {
    button.setAttribute("aria-pressed", String(button.dataset.sessionFilter === sessionFilter));
  }
}

function renderSessions() {
  const transferring = monitorSessions.filter(transferActive);
  const sessions = sessionFilter === "active" ? transferring : monitorSessions;
  $("sessions-detail").textContent = monitorSessions.length + " 个在线 · " + transferring.length + " 个传输中";
  $("sessions-empty").hidden = sessions.length > 0;
  $("sessions-empty").textContent = sessionFilter === "active" ? "暂无正在传输的会话。" : "暂无活动会话。";
  $("admin-sessions").replaceChildren(...[...sessions].sort((a, b) =>
    Number(transferActive(b)) - Number(transferActive(a)) || String(a.id).localeCompare(String(b.id))
  ).map((session) => {
    const account = node("div");
    account.append(node("div", session.user, "session-account"), node("small", [session.id, roleName[session.role]].filter(Boolean).join(" · "), "session-note"));
    const status = node("div");
    const tag = node("span", transferActive(session) ? "传输中" : "空闲", "session-tag");
    tag.dataset.active = String(transferActive(session));
    status.append(tag);
    if (transferActive(session)) status.append(node("small", "收 " + (session.incoming || 0) + " · 发 " + (session.outgoing || 0), "session-note"));
    const client = node("div", session.peer || "—");
    client.append(node("small", session.rate ? "带宽上限 " + rate(session.rate) : "带宽上限 —", "session-note"));
    const age = node("div", duration(session.since));
    age.append(node("small", (session.requests ?? "—") + " 次请求", "session-note"));
    return tableRow(account, status, client, bytes(session.received), bytes(session.sent), age);
  }));
}

function renderMonitorEvents(events) {
  const recent = [...events].reverse().slice(0, 5);
  $("monitor-events-empty").hidden = recent.length > 0;
  $("monitor-events").replaceChildren(...recent.map((event) => {
    let tone = "other";
    let symbol = "·";
    if (event.action.startsWith("put_")) [tone, symbol] = ["input", "↓"];
    else if (event.action.startsWith("get_")) [tone, symbol] = ["output", "↑"];
    else if (event.action.startsWith("share")) [tone, symbol] = ["relay", "⇄"];
    const icon = node("span", symbol, "monitor-event-icon");
    icon.dataset.tone = tone;
    icon.setAttribute("aria-hidden", "true");
    const summary = node("div", undefined, "monitor-event-description");
    const clock = node("time", stamp(event.time));
    if (event.time) clock.dateTime = event.time;
    summary.append(node("b", eventNames[event.action] || event.action), clock);
    const detail = node("small", [event.user, event.name || event.recipient, event.status].filter(Boolean).join(" · "), "monitor-event-detail");
    detail.title = detail.textContent;
    const main = node("div");
    main.append(summary, detail);
    const row = node("li");
    row.append(icon, main);
    return row;
  }));
}

function renderAdmin(data) {
  accepting = Boolean(data.accepting);
  markLink(accepting ? "online" : "offline", accepting ? "接受新连接" : "暂停新连接");
  if ($("notice").dataset.kind === "connection") notice("");
  const sessions = data.sessions || [];
  const accounts = data.accounts || [];
  const events = data.events || [];
  $("admin-online").textContent = sessions.length;
  $("admin-capacity").textContent = " / " + (data.capacity ?? "—");
  const capacity = Number(data.capacity);
  const used = capacity ? Math.round(sessions.length / capacity * 100) : 0;
  $("admin-utilization").value = used;
  $("admin-utilization-text").textContent = capacity ? used + "% 已用" : "容量未知";
  $("admin-address").textContent = data.address || "等待传输服务上线";
  $("admission").textContent = accepting ? "暂停新连接" : "恢复接入";
  updateTraffic(data.traffic);
  monitorSessions = sessions;
  if (route === "monitor") {
    renderSessions();
    renderMonitorEvents(events);
    refreshHistory();
  }
  $("member-count").textContent = accounts.length + " 个账号";
  const key = JSON.stringify([accounts, data.users]);
  if (accountKey !== key) {
    accountKey = key;
    const realRates = new Map((data.users || []).map((entry) => [entry.id, entry.rate]));
    $("admin-users").replaceChildren(...accounts.map((account) => {
      const enabled = account.enabled !== false;
      const pill = node("span", enabled ? "启用" : "停用", "pill");
      pill.dataset.variant = enabled ? "on" : "off";
      const actions = node("div", undefined, "cell-actions account-actions");
      if (account.role !== "admin") {
        actions.append(action(enabled ? "停用" : "启用", async () => {
          if (enabled && !window.confirm("停用 " + account.username + " 后，该账号当前登录和传输会话会断开。")) return;
          await post("/api/admin/users/" + encodeURIComponent(account.username) + "/state", {enabled: !enabled});
          notice("账号状态已更新。");
          refresh();
        }),
        accountDialogAction(account, "password", "重置密码", "secondary compact"),
        accountDialogAction(account, "delete", "删除账号", "danger compact"));
      }
      const rate = realRates.get(account.username) || roleRate[account.role];
      return tableRow(account.username, roleName[account.role] || account.role, rate ? bytes(rate) + "/s" : "—", pill, actions);
    }));
  }
  $("admin-events").replaceChildren(...[...events].reverse().slice(0, 60).map((event) => {
    const target = [event.name, event.recipient].filter(Boolean).join(" → ");
    const result = (event.status || "—") + (event.offset ? " · 偏移 " + bytes(event.offset) : "");
    return tableRow(stamp(event.time), event.user || "—", event.session || "—",
      eventNames[event.action] || event.action, target || "—", result);
  }));
  $("events-empty").hidden = events.length > 0;
}

function accountDialogAction(account, mode, label, className) {
  const button = node("button", label, className);
  button.type = "button";
  button.addEventListener("click", () => openAccountDialog(account, mode, button));
  return button;
}

function openAccountDialog(account, mode, trigger) {
  if (user?.role !== "admin" || account.role === "admin" || $("manage-account").open) return;
  const deleting = mode === "delete";
  managedAccount = account.username;
  accountActionTrigger = trigger;
  $("manage-account-title").textContent = (deleting ? "删除账号 " : "重置密码 · ") + account.username;
  $("manage-account-detail").textContent = deleting
    ? "删除后该账号将退出登录并失去文件访问权限。系统保留已有文件和操作记录，原用户名不能重新注册。"
    : "重置后该账号的现有会话会退出，需使用新密码重新登录。" + (account.enabled === false ? "账号仍保持停用状态。" : "");
  $("reset-member-password").hidden = deleting;
  $("delete-member-account").hidden = !deleting;
  $("reset-member-name").value = account.username;
  notice("", "note", "manage-account-notice");
  $("manage-account").showModal();
  $(deleting ? "confirm-member-name" : "member-new-password").focus();
}

function accountDialogBusy() {
  return Boolean($("manage-account").querySelector('form:not([hidden]) button[type="submit"]:disabled'));
}

$("manage-account").addEventListener("cancel", (event) => {
  if (accountDialogBusy()) event.preventDefault();
});
$("manage-account").addEventListener("close", () => {
  if ($("manage-account").open) return;
  const trigger = accountActionTrigger;
  managedAccount = null;
  accountActionTrigger = null;
  $("reset-member-password").reset();
  $("delete-member-account").reset();
  notice("", "note", "manage-account-notice");
  if (user?.role === "admin" && route === "accounts") {
    if (trigger?.isConnected) trigger.focus();
    else $("route-name").focus();
  }
});
for (const button of document.querySelectorAll("[data-dismiss-account]")) {
  button.addEventListener("click", () => {
    if (!accountDialogBusy()) $("manage-account").close();
  });
}

formHandler("reset-member-password", async (data) => {
  const username = managedAccount;
  if (!username) return;
  const size = utf8.encode(data.new_password).length;
  if (size < 10 || size > 128) throw new Error("新密码长度应为 10–128 字节。");
  if (data.new_password !== data.confirm_password) throw new Error("两次输入的密码不一致。");
  await post("/api/admin/users/" + encodeURIComponent(username) + "/password", {new_password: data.new_password});
  $("manage-account").close();
  notice(username + " 的密码已重置，旧会话已退出。");
  refresh();
}, "manage-account-notice");

formHandler("delete-member-account", async (data) => {
  const username = managedAccount;
  if (!username) return;
  if (data.confirm_username !== username) throw new Error("请输入与所选账号完全一致的用户名。");
  await post("/api/admin/users/" + encodeURIComponent(username) + "/delete", {confirm_username: data.confirm_username});
  $("manage-account").close();
  notice("账号 " + username + " 已删除。");
  refresh();
}, "manage-account-notice");

async function refresh() {
  if (!user || polling === revision) return;
  const current = revision;
  polling = current;
  try {
    if (user.role === "admin") {
      const state = await request("/api/admin/state");
      if (current === revision) renderAdmin(state);
    } else {
      const state = await request("/api/state");
      if (current !== revision) return;
      renderConnection(state.status, state.problem || "");
      renderFiles(state.files || []);
      renderTasks(state.tasks || []);
      if (route === "sharing" && Date.now() - lastSharePoll > 2400) {
        await refreshShare(current);
      }
    }
  } catch (error) {
    if (current !== revision) return;
    if (error.status === 401) showAuth("登录已失效，请重新登录。", "error");
    else if ($("notice").hidden || $("notice").dataset.kind === "connection") notice(error.message, "connection");
  } finally {
    if (polling === current) polling = undefined;
  }
}

function sendUploads() {
  while (user && staging < 2 && uploads.length) {
    const file = uploads.shift();
    const current = revision;
    const data = new FormData();
    data.append("file", file, file.name);
    staging++;
    post("/api/upload", data)
      .then(() => { if (current === revision) refresh(); })
      .catch((error) => { if (current === revision) notice(file.name + " · " + error.message, "error"); })
      .finally(() => { staging--; sendUploads(); });
  }
}

$("choose-login").addEventListener("click", () => authMode(false));
$("choose-register").addEventListener("click", () => authMode(true));
for (const link of document.querySelectorAll("[data-route]")) {
  link.addEventListener("click", () => showRoute(link.dataset.route));
}

formHandler("login-form", async (data, form) => {
  const result = await post("/api/auth/login", data);
  form.reset();
  openWorkspace(result.user ? result : await request("/api/auth/me"));
}, "auth-notice");

formHandler("register-form", async (data, form) => {
  await post("/api/auth/register", data);
  form.reset();
  authMode(false);
  $("login-name").value = data.username;
  notice("账号已创建，请登录。", "note", "auth-notice");
  $("login-form").elements.password.focus();
}, "auth-notice");

formHandler("password-form", async (data, form) => {
  await post("/api/auth/password", data);
  form.reset();
  showAuth("密码已更新，请用新密码登录。");
});

formHandler("send-form", async (data, form) => {
  if (!data.name && !data.message.trim()) throw new Error("请选择文件或填写留言。");
  await post("/api/share", data);
  form.reset();
  updateMessageLength();
  renderShareLimit();
  notice("已由服务端送达接收人的收件箱。");
});

$("logout").addEventListener("click", async () => {
  try {
    await post("/api/auth/logout");
    showAuth("已退出登录。");
  } catch (error) { showProblem(error); }
});

$("upload").addEventListener("click", () => $("selected-files").click());
$("selected-files").addEventListener("change", () => {
  const files = [...$("selected-files").files];
  $("selected-files").value = "";
  if (files.length + staging + uploads.length > 16) {
    notice("本次最多选择 16 个文件。", "error");
    return;
  }
  const valid = files.filter((file) => file.size <= 64 * 1024 * 1024);
  if (valid.length !== files.length) notice("已略过大于 64 MiB 的文件。", "error");
  uploads.push(...valid);
  sendUploads();
});

$("reconnect").addEventListener("click", async () => {
  $("reconnect").disabled = true;
  try {
    const before = linkSession;
    await post("/api/reconnect");
    notice(before ? "已请求重连，原会话 " + before + "。进行中的任务会尝试续传。" : "已请求连接。");
    refresh();
  } catch (error) { showProblem(error); }
  finally { $("reconnect").disabled = false; }
});

$("admission").addEventListener("click", async () => {
  $("admission").disabled = true;
  try {
    await post("/api/admin/admission", {accepting: !accepting});
    notice("接入状态已更新，已有连接可继续传输。");
    refresh();
  } catch (error) { showProblem(error); }
  finally { $("admission").disabled = false; }
});

$("refresh-admin").addEventListener("click", refresh);
$("monitor-audit").addEventListener("click", () => showRoute("audit"));
for (const button of document.querySelectorAll("[data-monitor-range]")) {
  button.addEventListener("click", () => {
    const key = button.dataset.monitorRange;
    if (!historyRanges[key] || key === historyRange) return;
    historyRange = key;
    historyData = null;
    selectedSample = null;
    $("chart-announcement").textContent = "";
    for (const candidate of document.querySelectorAll("[data-monitor-range]")) {
      candidate.setAttribute("aria-pressed", String(candidate === button));
    }
    renderHistory();
    refreshHistory(true);
  });
}
for (const button of document.querySelectorAll("[data-session-filter]")) {
  button.addEventListener("click", () => {
    sessionFilter = button.dataset.sessionFilter;
    updateSessionFilter();
    renderSessions();
  });
}
$("traffic-chart").addEventListener("pointermove", chartPointer);
$("traffic-chart").addEventListener("pointerdown", chartPointer);
$("traffic-chart").addEventListener("pointerleave", () => selectSample(null));
$("traffic-chart").addEventListener("keydown", chartKeyboard);
$("traffic-chart").addEventListener("blur", () => selectSample(null, true));
$("refresh-inbox").addEventListener("click", () => {
  lastSharePoll = 0;
  refresh();
});
$("recipients").addEventListener("change", renderShareLimit);
$("send-message").addEventListener("input", updateMessageLength);
for (const button of document.querySelectorAll("[data-mailbox]")) {
  button.addEventListener("click", () => {
    if (mailbox === button.dataset.mailbox) return;
    mailbox = button.dataset.mailbox;
    lastSharePoll = 0;
    for (const candidate of document.querySelectorAll("[data-mailbox]")) {
      candidate.setAttribute("aria-pressed", String(candidate === button));
    }
    $("inbox").replaceChildren();
    $("inbox-empty").hidden = false;
    $("inbox-empty").textContent = "正在读取互传记录…";
    refresh();
  });
}
for (const button of document.querySelectorAll("[data-filter]")) {
  button.addEventListener("click", () => {
    filter = button.dataset.filter;
    for (const candidate of document.querySelectorAll("[data-filter]")) {
      candidate.setAttribute("aria-pressed", String(candidate === button));
    }
    renderTasks(taskState);
  });
}

window.addEventListener("resize", drawChart);
request("/api/entry").then(showEntry).catch(() => {
  // The default login remains available if the entry directory is unreachable.
});
request("/api/auth/me").then(openWorkspace).catch((error) => {
  if (error.status !== 401) notice(error.message, "error", "auth-notice");
});
setInterval(refresh, 800);
