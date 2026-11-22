"use strict";

const item = (id) => document.getElementById(id);
const page = {
  account: item("account"), bandwidth: item("bandwidth"), session: item("session"), protocol: item("protocol"),
  connection: item("connection"), connectionText: item("connection-text"), notice: item("notice"),
  files: item("files"), fileTotal: item("file-total"), filesEmpty: item("files-empty"), filesMessage: item("files-message"),
  upload: item("upload"), selectedFiles: item("selected-files"), reconnect: item("reconnect"),
  tasks: item("tasks"), taskTotal: item("task-total"), tasksEmpty: item("tasks-empty"), tasksMessage: item("tasks-message"),
  fileRow: item("file-row"), taskRow: item("task-row"),
};

const token = document.querySelector('meta[name="client-token"]').content;
const filterButtons = [...document.querySelectorAll("[data-filter]")];
const taskRows = new Map();
const stateLabels = {running: "传输中", pausing: "暂停中", paused: "已暂停", done: "校验通过", failed: "失败"};
const transferStates = ["running", "pausing", "paused"];
const units = ["B", "KiB", "MiB", "GiB"];
const countFormatter = new Intl.NumberFormat("zh-CN", {maximumFractionDigits: 1});
let selectedFilter = "all";
let latestTasks = [];
let latestFileKey = "";
let pendingRefresh;
let connected = false;
let noticeTimer;
let uploadQueue = [];
let activeStaging = 0;

function bytes(value) {
  let current = Math.max(0, Number(value) || 0);
  let unit = 0;
  while (current >= 1024 && unit < units.length - 1) {
    unit++;
    current /= 1024;
  }
  return `${countFormatter.format(current)} ${units[unit]}`;
}

function setNotice(text, kind = "note") {
  clearTimeout(noticeTimer);
  page.notice.hidden = !text;
  page.notice.textContent = text;
  page.notice.dataset.kind = kind;
  if (text && kind !== "connection") {
    noticeTimer = setTimeout(() => { page.notice.hidden = true; }, 6000);
  }
}

async function request(path, data) {
  const headers = {"X-Client-Token": token};
  let body;
  if (data instanceof FormData) {
    body = data;
  } else if (data !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(data);
  }
  const response = await fetch(path, {method: "POST", headers, body, cache: "no-store"});
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || `请求失败 (${response.status})`);
  return value;
}

function renderConnection(status, problem) {
  connected = Boolean(status) && !problem;
  page.connection.dataset.state = connected ? "online" : problem ? "offline" : "connecting";
  page.connectionText.textContent = connected ? "已连接" : problem ? "连接异常" : "正在连接";
  page.connection.title = problem || "";
  const role = status?.role === "vip" ? "VIP" : "普通用户";
  page.account.textContent = status ? `${status.user} · ${role}` : "—";
  page.bandwidth.textContent = status ? `${bytes(status.rate)}/s` : "—";
  page.session.textContent = status?.session || "—";
  page.session.title = status?.session || "";
  page.protocol.textContent = status?.tls || "—";
  page.upload.disabled = !connected;
  const connectionNotice = page.notice.dataset.kind === "connection";
  if (problem && (page.notice.hidden || page.notice.dataset.kind !== "error")) {
    setNotice(problem, "connection");
  } else if (connected && connectionNotice) {
    setNotice("");
  }
}

function renderFiles(files, problem) {
  const fileKey = JSON.stringify([connected, Boolean(problem), files]);
  if (latestFileKey === fileKey) return;
  latestFileKey = fileKey;
  page.fileTotal.textContent = connected ? `${files.length} 个文件` : "等待服务器";
  page.filesEmpty.hidden = files.length > 0;
  page.filesMessage.textContent = connected ? "远端目录暂无文件" : "连接后显示远端文件";
  page.files.replaceChildren(...files.map((file) => {
    const row = page.fileRow.content.firstElementChild.cloneNode(true);
    const name = row.querySelector(".file-name");
    name.textContent = file.name;
    name.title = file.name;
    const hash = row.querySelector(".file-hash");
    if (file.sha256) {
      hash.textContent = `SHA-256 ${file.sha256.slice(0, 14)}…`;
      hash.title = file.sha256;
    }
    row.querySelector(".file-size").textContent = bytes(file.size);
    const button = row.querySelector("button");
    button.disabled = !connected;
    button.setAttribute("aria-label", `下载 ${file.name}`);
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await request("/api/download", {name: file.name});
        await refresh();
      } catch (error) {
        setNotice(error.message, "error");
      } finally {
        button.disabled = !connected;
      }
    });
    return row;
  }));
}

function taskButton(id, state, title) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "button secondary compact";
  button.textContent = title;
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await request(`/api/tasks/${id}/${state}`);
      await refresh();
    } catch (error) {
      setNotice(error.message, "error");
    } finally {
      button.disabled = false;
    }
  });
  return button;
}

function renderTask(task) {
  let row = taskRows.get(task.id);
  if (!row) {
    row = page.taskRow.content.firstElementChild.cloneNode(true);
    row.dataset.id = task.id;
    taskRows.set(task.id, row);
    const direction = row.querySelector(".direction");
    direction.dataset.direction = task.direction;
    direction.title = task.direction === "upload" ? "上传" : "下载";
    direction.textContent = task.direction === "upload" ? "↑" : "↓";
    const name = row.querySelector(".task-name");
    name.textContent = task.name;
    name.title = task.name;
  }
  const actions = row.querySelector(".task-actions");
  const actionKey = `${task.state}/${Boolean(task.saved)}`;
  if (actions.dataset.key !== actionKey) {
    actions.dataset.key = actionKey;
    actions.replaceChildren();
    if (task.state === "running") actions.append(taskButton(task.id, "pause", "暂停"));
    if (task.state === "paused") actions.append(taskButton(task.id, "resume", "继续"));
    if (task.state === "done" && task.saved) {
      const link = document.createElement("a");
      link.className = "button secondary compact";
      link.textContent = "另存";
      link.href = `/api/files/${task.id}`;
      link.download = task.name;
      actions.append(link);
    }
  }
  row.dataset.state = task.state;
  row.querySelector(".task-state").textContent = stateLabels[task.state] || task.state;
  const progress = row.querySelector("progress");
  progress.value = task.state === "done" ? 100 : (task.total ? Math.min(100, task.done / task.total * 100) : 0);
  const measurement = `${bytes(task.done)} / ${bytes(task.total)}${task.rate ? ` · ${bytes(task.rate)}/s` : ""}`;
  row.querySelector(".task-size").textContent = measurement;
  const details = row.querySelector(".task-detail");
  const messages = [];
  if (task.resumed_at > 0) messages.push(`从 ${bytes(task.resumed_at)} 续传`);
  if (task.state === "done" && task.sha256) messages.push(`SHA-256 ${task.sha256.slice(0, 14)}…`);
  if (task.error) messages.push(task.error);
  details.textContent = messages.join(" · ");
  details.title = task.sha256 || "";
  return row;
}

function renderTasks(tasks) {
  latestTasks = tasks;
  const active = tasks.filter((task) => transferStates.includes(task.state));
  page.taskTotal.textContent = `${tasks.length} 个任务${active.length ? ` · ${active.length} 个进行中` : ""}`;
  const visible = selectedFilter === "active" ? active : selectedFilter === "done" ? tasks.filter((task) => task.state === "done") : tasks;
  const current = new Set(tasks.map(({id}) => id));
  for (const id of taskRows.keys()) if (!current.has(id)) taskRows.delete(id);
  const rows = visible.map(renderTask);
  if (page.tasks.children.length !== rows.length || rows.some((row, index) => page.tasks.children[index] !== row)) {
    page.tasks.replaceChildren(...rows);
  }
  page.tasksEmpty.hidden = rows.length > 0;
  page.tasksMessage.textContent = selectedFilter === "active" ? "暂无进行中的任务" : selectedFilter === "done" ? "暂无已完成的任务" : "暂无传输任务";
}

function refresh() {
  if (pendingRefresh) return pendingRefresh;
  pendingRefresh = fetch("/api/state", {cache: "no-store"})
    .then((response) => {
      if (!response.ok) throw new Error(`无法读取客户端状态 (${response.status})`);
      return response.json();
    })
    .then(({status, problem, files, tasks}) => {
      renderConnection(status, problem);
      renderFiles(files || [], problem);
      renderTasks(tasks || []);
    })
    .catch((error) => {
      renderConnection(null, error.message);
    })
    .finally(() => { pendingRefresh = undefined; });
  return pendingRefresh;
}

function sendUploads() {
  while (activeStaging < 2 && uploadQueue.length) {
    const file = uploadQueue.shift();
    activeStaging++;
    const data = new FormData();
    data.append("file", file, file.name);
    request("/api/upload", data)
      .then(refresh)
      .catch((error) => setNotice(`${file.name} · ${error.message}`, "error"))
      .finally(() => { activeStaging--; sendUploads(); });
  }
}

page.upload.addEventListener("click", () => page.selectedFiles.click());
page.selectedFiles.addEventListener("change", () => {
  const files = [...page.selectedFiles.files];
  page.selectedFiles.value = "";
  if (files.length === 0) return;
  if (files.length + uploadQueue.length + activeStaging > 16) {
    setNotice("每次最多选择 16 个文件", "error");
    return;
  }
  uploadQueue.push(...files);
  sendUploads();
});

page.reconnect.addEventListener("click", async () => {
  page.reconnect.disabled = true;
  const oldSession = page.session.textContent;
  try {
    await request("/api/reconnect");
    await refresh();
    setNotice(oldSession === "—" ? "已发起连接" : `已请求重连，原会话 ${oldSession}`);
  } catch (error) {
    setNotice(error.message, "error");
  } finally {
    page.reconnect.disabled = false;
  }
});

for (const button of filterButtons) {
  button.addEventListener("click", () => {
    selectedFilter = button.dataset.filter;
    for (const candidate of filterButtons) {
      candidate.setAttribute("aria-pressed", String(candidate === button));
    }
    renderTasks(latestTasks);
  });
}

refresh();
setInterval(refresh, 400);
