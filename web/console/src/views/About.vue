<template>
  <div>
    <el-card shadow="never" style="margin-bottom:16px">
      <div class="km-title">关于 KingMoat WAF</div>
      <div class="km-set-row"><div class="grow"><div class="set-name">产品名称</div></div><span>{{ productName }}</span></div>
      <div class="km-set-row"><div class="grow"><div class="set-name">版本</div></div><span class="km-mono">{{ aboutVersion }}</span></div>
      <div class="km-set-row"><div class="grow"><div class="set-name">检测内核</div></div>
        <span class="km-mono" style="font-size:12.5px">{{ engine.coraza ? 'Coraza ' + engine.coraza : 'Coraza' }} + {{ engine.crs ? 'OWASP CRS ' + engine.crs : 'OWASP CRS' }} + libinjection</span></div>
      <div class="km-set-row"><div class="grow"><div class="set-name">上游发布</div></div>
        <span class="km-mono" style="font-size:12.5px">
          Coraza {{ engine.coraza_release || '-' }} · CRS {{ engine.crs_release || '-' }} · Go {{ engine.go_release || '-' }}
          <template v-if="engine.geoip_build">· GeoIP {{ engine.geoip_build }}</template>
        </span></div>
      <div class="km-set-row"><div class="grow"><div class="set-name">运行时</div></div><span class="km-mono">{{ engine.go || '-' }}</span></div>
      <div class="km-set-row"><div class="grow"><div class="set-name">开源许可</div></div><a href="https://opensource.org/license/mulanpsl-2-0" target="_blank" style="text-decoration:none"><el-tag size="small" effect="plain" class="km-tag">MulanPSL-2.0 ↗</el-tag></a></div>
      <div class="km-set-row"><div class="grow"><div class="set-name">GeoIP 数据</div></div>
        <span style="font-size:12.5px">IP Geolocation by <a href="https://db-ip.com" target="_blank" style="color:var(--km-cyan)">DB-IP</a>（Country Lite，CC BY 4.0，内置随版本发布）</span></div>
      <div class="km-set-row"><div class="grow"><div class="set-name">Slogan</div></div><span style="font-size:12.5px;color:var(--km-cyan)">固若金汤，御攻于无形 — Fortress for Every Request</span></div>
      <div class="km-set-row"><div class="grow"><div class="set-name">发布者 / 联系人</div></div><span class="km-mono"><a href="mailto:ailife2@126.com" style="color:var(--km-cyan);text-decoration:none">ailife2@126.com</a></span></div>
      <div class="km-set-row">
        <div class="grow"><div class="set-name">技术支持</div><div class="set-desc">部署、集成或功能定制需要协助时可直接邮件联系</div></div>
        <span style="font-size:12.5px;color:var(--km-cyan)">如需有偿技术支持可联系作者：<a href="mailto:ailife2@126.com" style="color:var(--km-cyan)">ailife2@126.com</a></span>
      </div>
      <div class="km-set-row">
        <div class="grow"><div class="set-name">源码仓库</div></div>
        <span class="km-mono" style="font-size:12.5px">
          <a href="https://github.com/KingMoat/KingMoat-WAF" target="_blank" style="color:var(--km-cyan)">github.com/KingMoat/KingMoat-WAF</a>
          &nbsp;·&nbsp;
          <a href="https://gitee.com/kingmoat/KingMoat-WAF" target="_blank" style="color:var(--km-cyan)">gitee.com/kingmoat/KingMoat-WAF</a>
        </span>
      </div>
      <div class="km-set-row">
        <div class="grow"><div class="set-name">OpenAPI 接口文档</div><div class="set-desc">在线 Swagger 见「API 文档」页；此处可查看清单与下载</div></div>
        <el-button size="small" @click="openApiDoc">查看接口清单</el-button>
        <el-button size="small" type="primary" @click="downloadOpenAPI">下载 JSON</el-button>
      </div>
    </el-card>

    <el-dialog v-model="apiDlg" title="OpenAPI 接口清单" width="720px">
      <div style="display:flex;gap:8px;margin-bottom:10px;align-items:center">
        <el-tag size="small" effect="plain" class="km-tag">{{ apiInfo.version || 'OpenAPI' }}</el-tag>
        <el-tag size="small" effect="plain" type="success" class="km-tag">{{ apiCount }} 个操作</el-tag>
        <div style="flex:1"></div>
        <el-button size="small" @click="downloadOpenAPI">下载 JSON</el-button>
      </div>
      <div style="max-height:52vh;overflow:auto;border:1px solid var(--km-line);border-radius:8px">
        <table style="width:100%;border-collapse:collapse;font-size:12.5px">
          <thead><tr style="text-align:left;background:var(--km-panel-2)">
            <th style="padding:8px 12px;width:70px">方法</th><th style="padding:8px 12px">路径</th><th style="padding:8px 12px;width:220px">说明</th>
          </tr></thead>
          <tbody>
            <tr v-for="(o, i) in apiOps" :key="i" style="border-top:1px solid var(--km-line-soft)">
              <td style="padding:6px 12px"><el-tag size="small" effect="dark" :type="o.method === 'get' ? 'primary' : o.method === 'delete' ? 'danger' : 'success'" class="km-tag">{{ o.method.toUpperCase() }}</el-tag></td>
              <td style="padding:6px 12px" class="km-mono">{{ o.path }}</td>
              <td style="padding:6px 12px" class="km-dim">{{ o.summary }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'

const engine = ref({})
const aboutVersion = ref('-')
const productName = ref('KingMoat WAF')
const apiDlg = ref(false)
const apiOps = ref([])
const apiInfo = ref({})
const apiCount = computed(() => apiOps.value.length)

async function openApiDoc() {
  try {
    const spec = await fetch('/openapi.json').then(r => r.json())
    apiInfo.value = { version: spec.info?.version || 'OpenAPI' }
    const ops = []
    for (const [path, methods] of Object.entries(spec.paths || {})) {
      for (const [m, op] of Object.entries(methods)) {
        if (['get', 'post', 'put', 'patch', 'delete'].includes(m)) {
          ops.push({ method: m, path, summary: op.summary || op.description?.slice(0, 40) || '' })
        }
      }
    }
    apiOps.value = ops
    apiDlg.value = true
  } catch (e) {
    ElMessage.error('OpenAPI 获取失败：' + e.message)
  }
}

function downloadOpenAPI() {
  window.open('/openapi.json', '_blank')
}

onMounted(() => {
  api('/api/status').then(s => {
    aboutVersion.value = (s.version || '-') + ' · rev ' + (s.revision ?? '-')
    engine.value = s.engine || {}
  }).catch(() => {})
})
</script>
