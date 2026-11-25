<script setup>
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { marked } from 'marked'
import DOMPurify from 'dompurify'
const logs = ref([]), selected = ref(''), file = ref(null), source = ref('existing')
const job = ref(null), history = ref([]), error = ref(''), busy = ref(false)
const analysisHtml = computed(() => DOMPurify.sanitize(marked.parse(job.value?.result?.agents?.presentation || job.value?.result?.agents?.analysis || ''), { FORBID_TAGS: ['img', 'style'] }))
const originalAnalysisHtml = computed(() => DOMPurify.sanitize(marked.parse(job.value?.result?.agents?.analysis || ''), { FORBID_TAGS: ['img', 'style'] }))
const settings = ref({provider:'openai', profiles:{ollama:{base_url:'http://127.0.0.1:11434',model:''},openai:{base_url:'https://api.openai.com/v1',model:''}}, redact:true, api_key:'', has_api_key:false})
const settingsMessage = ref(''), saving = ref(false), testing = ref(false), testMessage = ref('')
const models = ref([]), loadingModels = ref(false), modelsMessage = ref('')
let modelsRequestId = 0
const savedSettings = ref('')
const configSnapshot = () => JSON.stringify([settings.value.provider,settings.value.profiles,settings.value.redact])
const hasUnsavedSettings = computed(() => configSnapshot() !== savedSettings.value || !!settings.value.api_key)
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
    if (['pending','running','recognizing','analyzing','rewriting'].includes(job.value.status)) timer = setTimeout(() => poll(id), 1000)
    else { busy.value = false; await refreshHistory() }
  } catch (e) { error.value = e.message; busy.value = false }
}
async function start() {
  error.value = ''
  if (hasUnsavedSettings.value) { error.value = '请先保存模型配置。'; return }
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
watch(() => [settings.value.provider, settings.value.profiles[settings.value.provider].base_url, settings.value.api_key], () => {
  modelsRequestId++; models.value = []; modelsMessage.value = ''; loadingModels.value = false
})
function changeProvider() { settingsMessage.value = '修改后请保存配置。'; testMessage.value = '' }
function selectModel(event) { if (event.target.value) settings.value.profiles[settings.value.provider].model = event.target.value }
async function fetchModels() {
  const requestId = ++modelsRequestId
  models.value = []; modelsMessage.value = ''; loadingModels.value = true
  try {
    const result = await api('/api/settings/models', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({provider:settings.value.provider, base_url:settings.value.profiles[settings.value.provider].base_url, api_key:settings.value.api_key || null})})
    if (requestId !== modelsRequestId) return
    models.value = result.models
    modelsMessage.value = result.models.length ? `获取到 ${result.models.length} 个模型，请在下拉列表中选择。` : '未获取到可用模型，请手动输入模型名称。'
  } catch (e) { if (requestId === modelsRequestId) modelsMessage.value = e.message }
  finally { if (requestId === modelsRequestId) loadingModels.value = false }
}
async function saveSettings() {
  saving.value = true; settingsMessage.value = ''
  try {
    const saved = await api('/api/settings', {method:'PUT', headers:{'Content-Type':'application/json'}, body:JSON.stringify(settings.value)})
    settings.value = {...saved, api_key:''}; savedSettings.value = configSnapshot(); settingsMessage.value = '模型配置已保存。'
  } catch (e) { settingsMessage.value = e.message } finally { saving.value = false }
}
async function testConnection() {
  if (hasUnsavedSettings.value) { testMessage.value = '请先保存模型配置。'; return }
  testing.value = true; testMessage.value = ''
  try { await api('/api/settings/test', {method:'POST'}); testMessage.value = '连接成功，模型已响应。' }
  catch (e) { testMessage.value = e.message } finally { testing.value = false }
}
onMounted(async () => { try { logs.value = await api('/api/logs'); if (logs.value.length) selected.value = logs.value[0].name; settings.value = {...await api('/api/settings'), api_key:''}; savedSettings.value = configSnapshot(); await refreshHistory() } catch (e) { error.value = '无法连接本地服务，请检查启动脚本。' } })
onUnmounted(() => clearTimeout(timer))
</script>
<template>
  <div class="shell">
    <header><div class="brand"><span class="mark">D</span><div><strong>DataBot</strong><span>日志分析工作台</span></div></div><span class="status"><i></i>本地演示</span></header>
    <main>
      <div class="intro"><div><p class="eyebrow">日志巡检</p><h1>让日志中的问题<br>更容易被看见。</h1><p class="lead">选择日志，使用两个 Agent 识别和分析异常。</p></div><div class="step-note"><span>分析流程</span><strong>识别 → 分析</strong><p>结果保存在本机。飞书通知尚未接入。</p></div></div>
      <section class="panel model-panel"><div class="section-title"><div><span class="number">01</span><h2>模型配置</h2></div><p>两个 Agent 使用同一配置</p></div>
        <div class="settings-grid"><div><label for="provider">接入方式</label><select id="provider" v-model="settings.provider" @change="changeProvider"><option value="openai">外部 OpenAI 兼容 API</option><option value="ollama">本机 Ollama</option></select></div><div><label for="base">服务地址</label><input id="base" v-model.trim="settings.profiles[settings.provider].base_url" placeholder="模型服务地址"></div><div><label for="model">模型名称</label><input id="model" v-model.trim="settings.profiles[settings.provider].model" :placeholder="settings.provider === 'ollama' ? '例如 qwen3.5:35b-a3b' : '选择或手动填写模型名称'"><div class="model-list-control"><select aria-label="可用模型" :disabled="!models.length" :value="models.includes(settings.profiles[settings.provider].model) ? settings.profiles[settings.provider].model : ''" @change="selectModel"><option value="">{{models.length ? '选择模型' : '请先获取模型'}}</option><option v-for="model in models" :key="model" :value="model">{{model}}</option></select><button class="secondary" type="button" :disabled="loadingModels || busy || saving || testing" @click="fetchModels">{{loadingModels ? '获取中…' : '获取模型'}}</button></div><p v-if="modelsMessage" class="hint" role="status">{{modelsMessage}}</p></div><div v-if="settings.provider==='openai'"><label for="key">API 密钥</label><input id="key" v-model="settings.api_key" type="password" :placeholder="settings.has_api_key ? '已保存，留空保持不变' : '按服务要求填写'"></div></div>
        <label class="redact-choice"><input type="checkbox" v-model="settings.redact">发送给模型前脱敏</label><p class="hint">{{settings.redact ? '脱敏规则可能无法覆盖所有敏感信息。' : '已关闭脱敏，日志内容将发送给所选模型服务。'}} 远程 API 密钥以本机受限权限文件保存。切换接入方式不会覆盖另一套配置。</p><button class="secondary" :disabled="saving || busy || testing" @click="saveSettings">{{saving ? '保存中…' : '保存配置'}}</button> <button class="secondary" :disabled="saving || busy || testing" @click="testConnection">{{testing ? '测试中…' : '测试连接'}}</button><p class="hint">测试连接只发送简短测试文本，不发送日志；远程服务可能产生调用费用。</p><span v-if="settingsMessage" class="settings-message" role="status">{{settingsMessage}}</span><span v-if="testMessage" class="settings-message" role="status">{{testMessage}}</span>
      </section>
      <div class="layout">
        <section class="panel input-panel"><div class="section-title"><div><span class="number">02</span><h2>选择日志</h2></div><p>每次分析一份文件</p></div>
          <div class="tabs"><button :class="{active:source==='existing'}" @click="source='existing'">现有日志</button><button :class="{active:source==='upload'}" @click="source='upload'">上传文件</button></div>
          <div v-if="source==='existing'"><label for="log">选择 predict 目录中的日志</label><select id="log" v-model="selected"><option v-if="!logs.length" value="">未找到日志</option><option v-for="item in logs" :key="item.name" :value="item.name">{{item.name}}　·　{{size(item.size)}}</option></select><p class="hint">直接读取原始文件，不修改文件内容。</p></div>
          <div v-else><label for="file">选择 .log 或 .txt 文件</label><input id="file" type="file" accept=".log,.txt,text/plain" @change="file=$event.target.files[0]"><p class="hint">上传后在本机分析，最大支持 300 MiB。</p></div>
          <button class="primary" :disabled="busy" @click="start">{{busy ? '正在分析…' : '开始分析'}}</button><p v-if="error" class="error" role="alert">{{error}}</p>
        </section>
        <section class="panel result-panel"><div class="section-title"><div><span class="number">03</span><h2>分析结果</h2></div><p v-if="job">{{job.filename}}</p></div>
          <div v-if="!job" class="empty"><div class="empty-icon">⌁</div><strong>选择日志，开始第一次分析</strong><p>完成后将在这里显示异常统计与日志片段。</p></div>
          <div v-else-if="['pending','running','recognizing','analyzing','rewriting'].includes(job.status)" class="empty"><div class="spinner"></div><strong>{{job.status==='recognizing' ? '异常识别 Agent 正在识别' : job.status==='analyzing' ? '问题分析 Agent 正在分析' : job.status==='rewriting' ? '正在整理分析结果' : '正在扫描日志'}}</strong><p v-if="job.result?.recognition_progress">识别覆盖：{{size(job.result.recognition_progress.processed_bytes)}} / {{size(job.result.recognition_progress.total_bytes)}}，{{job.result.recognition_progress.chunks}} 个片段</p><p>大文件可能需要一些时间，请保持页面打开。</p></div>
          <div v-else-if="job.status==='failed'" class="empty"><strong>分析未完成</strong><p class="error">{{job.error}}</p><p v-if="job.result?.recognition_progress">识别覆盖：{{size(job.result.recognition_progress.processed_bytes)}} / {{size(job.result.recognition_progress.total_bytes)}}</p></div>
          <div v-else-if="job.result"><div class="result-meta">{{job.status==='partial' ? '部分识别，未覆盖全部日志' : job.result.agents ? '两个 Agent 已完成' : '规则扫描记录'}} <span>{{job.elapsed}} 秒</span></div><div class="metrics"><div><span>日志记录</span><strong>{{job.result.counts.records.toLocaleString()}}</strong></div><div><span>错误记录</span><strong>{{job.result.counts.error.toLocaleString()}}</strong></div><div><span>警告记录</span><strong>{{job.result.counts.warning.toLocaleString()}}</strong></div></div><p class="hint">规则统计可能重叠；本地展示的片段可能含敏感信息。</p>
            <template v-if="job.result.agents">
              <p class="hint">模型识别覆盖：{{size(job.result.agents.recognition.processed_bytes)}} / {{size(job.result.agents.recognition.total_bytes)}}<span v-if="!job.result.agents.recognition.complete">，剩余日志未识别</span>。</p>
              <h3>问题分析 Agent <span v-if="job.result.agents.analysis_elapsed != null">· {{job.result.agents.analysis_elapsed}} 秒</span></h3>
              <p v-if="job.result.agents.presentation_status === 'failed' || job.result.agents.presentation_status === 'skipped'" class="hint">表达优化未完成，当前显示原始分析结果。</p>
              <p v-if="job.result.agents.presentation" class="hint">以下内容由模型整理，请结合原始分析和日志核查。</p>
              <div class="analysis-markdown" v-html="analysisHtml"></div>
              <details v-if="job.result.agents.presentation" class="result-details">
                <summary>查看原始分析结果</summary>
                <div class="analysis-markdown" v-html="originalAnalysisHtml"></div>
              </details>
              <details class="result-details">
                <summary>查看异常识别 Agent 的发现（{{job.result.agents.recognition.findings.length}} 条）</summary>
                <p class="hint">模型已识别 {{size(job.result.agents.recognition.processed_bytes)}} / {{size(job.result.agents.recognition.total_bytes)}}，共 {{job.result.agents.recognition.chunks}} 个片段。<span v-if="job.result.agents.recognition.elapsed != null">识别耗时 {{job.result.agents.recognition.elapsed}} 秒。</span><span v-if="job.result.agents.recognition.note">{{job.result.agents.recognition.note}}。</span><span v-if="job.result.agents.recognition.omitted_findings">另有 {{job.result.agents.recognition.omitted_findings}} 条识别结果未纳入后续分析。</span></p>
                <p v-if="!job.result.agents.recognition.findings.length" class="hint">已处理范围内未识别到异常。</p>
                <div v-for="(finding, index) in job.result.agents.recognition.findings" :key="index" class="example"><strong>{{finding.summary}}</strong><p class="hint">{{finding.severity}} · 片段 {{finding.chunk}} · {{finding.evidence_verified ? '证据与输入片段匹配' : '证据待核查'}}<span v-if="finding.line != null"> · 第 {{finding.line}} 行</span><span v-if="finding.occurrences > 1"> · 相同摘要 {{finding.occurrences}} 条</span></p><pre>{{finding.evidence}}</pre></div>
              </details>
            </template>
            <details class="result-details">
              <summary>查看规则扫描片段（{{job.result.examples.length}} 条）</summary>
              <p v-if="!job.result.examples.length" class="hint">未发现符合当前规则的错误或警告，不代表业务一定正常。</p>
              <div v-for="(item, index) in job.result.examples" :key="index" class="example"><div><span :class="item.type==='错误'?'badge error-badge':'badge'">{{item.type}}</span><span>第 {{item.line}} 行<span v-if="item.exception"> · {{item.exception}}</span></span></div><pre>{{item.excerpt}}</pre><small v-if="item.truncated">片段已截断</small></div>
            </details>
          </div>
        </section>
      </div>
      <section class="history"><div class="section-title"><div><span class="number">04</span><h2>最近分析</h2></div><p>保存在本机，最多显示 50 条</p></div><p v-if="!history.length" class="hint">暂无分析记录。</p><div v-else class="history-list"><button v-for="item in history" :key="item.id" @click="showHistory(item)"><span>{{item.filename}}</span><span>{{new Date(item.created_at).toLocaleString('zh-CN')}}　 ·　 {{item.status === 'completed' ? '已完成' : item.status === 'partial' ? '部分识别' : item.status === 'failed' ? '失败' : '进行中'}}</span></button></div></section>
    </main>
    <footer>DataBot · 本地日志分析演示</footer>
  </div>
</template>
