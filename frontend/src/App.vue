<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
const logs = ref([]), selected = ref(''), file = ref(null), source = ref('existing')
const job = ref(null), history = ref([]), error = ref(''), busy = ref(false)
let timer
const size = n => n >= 1048576 ? `${(n/1048576).toFixed(1)} MiB` : `${(n/1024).toFixed(1)} KiB`
async function api(url, opts) {
  const res = await fetch(url, opts)
  const body = await res.json()
  if (!res.ok) throw new Error(body.detail || '请求失败，请稍后重试')
  return body
}
async function refreshHistory() { history.value = await api('/api/analyses') }
async function poll(id) {
  try {
    job.value = await api(`/api/analyses/${id}`)
    if (['pending','running'].includes(job.value.status)) timer = setTimeout(() => poll(id), 1000)
    else { busy.value = false; await refreshHistory() }
  } catch (e) { error.value = e.message; busy.value = false }
}
async function start() {
  error.value = ''
  if (source.value === 'existing' && !selected.value || source.value === 'upload' && !file.value) { error.value = '请先选择一份日志。'; return }
  busy.value = true; job.value = null
  try {
    let task
    if (source.value === 'existing') task = await api('/api/analyze', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({filename:selected.value})})
    else { const form = new FormData(); form.append('file', file.value); task = await api('/api/upload', {method:'POST', body:form}) }
    await poll(task.id)
  } catch (e) { error.value = e.message; busy.value = false }
}
function showHistory(item) { if (!busy.value) { job.value = item; error.value = '' } }
onMounted(async () => { try { logs.value = await api('/api/logs'); if (logs.value.length) selected.value = logs.value[0].name; await refreshHistory() } catch (e) { error.value = '无法连接本地服务，请检查启动脚本。' } })
onUnmounted(() => clearTimeout(timer))
</script>
<template>
  <div class="shell">
    <header><div class="brand"><span class="mark">D</span><div><strong>DataBot</strong><span>日志分析工作台</span></div></div><span class="status"><i></i>本地演示</span></header>
    <main>
      <div class="intro"><div><p class="eyebrow">日志巡检</p><h1>让日志中的问题<br>更容易被看见。</h1><p class="lead">选择一份日志，快速查看错误和警告。分析结果会保存在本机。</p></div><div class="step-note"><span>当前阶段</span><strong>规则扫描</strong><p>模型分析与飞书通知将在后续接入。</p></div></div>
      <div class="layout">
        <section class="panel input-panel"><div class="section-title"><div><span class="number">01</span><h2>选择日志</h2></div><p>每次分析一份文件</p></div>
          <div class="tabs"><button :class="{active:source==='existing'}" @click="source='existing'">现有日志</button><button :class="{active:source==='upload'}" @click="source='upload'">上传文件</button></div>
          <div v-if="source==='existing'"><label for="log">选择 predict 目录中的日志</label><select id="log" v-model="selected"><option v-if="!logs.length" value="">未找到日志</option><option v-for="item in logs" :key="item.name" :value="item.name">{{item.name}}　·　{{size(item.size)}}</option></select><p class="hint">直接读取原始文件，不修改文件内容。</p></div>
          <div v-else><label for="file">选择 .log 或 .txt 文件</label><input id="file" type="file" accept=".log,.txt,text/plain" @change="file=$event.target.files[0]"><p class="hint">上传后在本机分析，最大支持 300 MiB。</p></div>
          <button class="primary" :disabled="busy" @click="start">{{busy ? '正在分析…' : '开始分析'}}</button><p v-if="error" class="error" role="alert">{{error}}</p>
        </section>
        <section class="panel result-panel"><div class="section-title"><div><span class="number">02</span><h2>分析结果</h2></div><p v-if="job">{{job.filename}}</p></div>
          <div v-if="!job" class="empty"><div class="empty-icon">⌁</div><strong>选择日志，开始第一次分析</strong><p>完成后将在这里显示异常统计与日志片段。</p></div>
          <div v-else-if="['pending','running'].includes(job.status)" class="empty"><div class="spinner"></div><strong>正在扫描日志</strong><p>大文件可能需要一些时间，请保持页面打开。</p></div>
          <div v-else-if="job.status==='failed'" class="empty"><strong>分析未完成</strong><p class="error">{{job.error}}</p></div>
          <div v-else-if="job.result"><div class="result-meta">规则扫描完成 <span>{{job.elapsed}} 秒</span></div><div class="metrics"><div><span>日志记录</span><strong>{{job.result.counts.records.toLocaleString()}}</strong></div><div><span>错误记录</span><strong>{{job.result.counts.error.toLocaleString()}}</strong></div><div><span>警告记录</span><strong>{{job.result.counts.warning.toLocaleString()}}</strong></div></div><p class="hint">{{job.result.note}} 仅展示前 {{job.result.example_limit}} 个片段，片段可能含敏感信息。</p><h3>异常与警告片段</h3><p v-if="!job.result.examples.length" class="hint">未发现符合当前规则的错误或警告，不代表业务一定正常。</p><div v-for="(item, index) in job.result.examples" :key="index" class="example"><div><span :class="item.type==='错误'?'badge error-badge':'badge'">{{item.type}}</span><span>第 {{item.line}} 行<span v-if="item.exception"> · {{item.exception}}</span></span></div><pre>{{item.excerpt}}</pre><small v-if="item.truncated">片段已截断</small></div></div>
        </section>
      </div>
      <section class="history"><div class="section-title"><div><span class="number">03</span><h2>最近分析</h2></div><p>保存在本机，最多显示 50 条</p></div><p v-if="!history.length" class="hint">暂无分析记录。</p><div v-else class="history-list"><button v-for="item in history" :key="item.id" @click="showHistory(item)"><span>{{item.filename}}</span><span>{{new Date(item.created_at).toLocaleString('zh-CN')}}　 ·　 {{item.status === 'completed' ? '已完成' : item.status === 'failed' ? '失败' : '进行中'}}</span></button></div></section>
    </main>
    <footer>DataBot · 本地日志分析演示</footer>
  </div>
</template>
