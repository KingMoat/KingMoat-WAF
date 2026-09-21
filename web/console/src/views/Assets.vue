<template>
  <el-card shadow="never">
    <div class="km-title">API 资产清单（被动学习）</div>
    <el-alert v-if="!enabled" type="info" :closable="false" show-icon
              title="API 资产学习未启用" description="在配置中设置 api_assets.enabled=true 并发布后开始学习流量。" style="margin-bottom:12px" />
    <el-table :data="assets" size="small">
      <el-table-column prop="site" label="站点" width="140" />
      <el-table-column prop="method" label="方法" width="80" />
      <el-table-column prop="path" label="路径（归一化）" class-name="km-mono" show-overflow-tooltip />
      <el-table-column label="标记" width="220">
        <template #default="{ row }">
          <el-tag v-for="t in row.tags || []" :key="t" size="small" effect="dark" class="km-tag" style="margin-right:4px">{{ t }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="hits" label="命中" width="90" />
      <el-table-column label="参数" show-overflow-tooltip>
        <template #default="{ row }">{{ (row.params || []).join(', ') }}</template>
      </el-table-column>
      <el-table-column label="最后可见" width="170">
        <template #default="{ row }">{{ fmtTime(row.last_seen) }}</template>
      </el-table-column>
      <el-table-column width="100">
        <template #default="{ row }">
          <el-button v-if="can('operator')" link type="warning" @click="ignore(row)">忽略</el-button>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api, can, post } from '../api'
import { fmtTime } from '../timefmt'

const assets = ref([])
const enabled = ref(true)
let timer = null

async function load() {
  try {
    const d = await api('/api/assets/apis')
    assets.value = d.assets || d || []
    enabled.value = d.enabled !== false
  } catch (e) { if (e.status !== 401) enabled.value = false }
}
async function ignore(row) {
  await post(`/api/assets/apis/${row.id}/ignore`)
  ElMessage.success('已忽略')
  load()
}
onMounted(() => { load(); timer = setInterval(load, 20000) })
onBeforeUnmount(() => clearInterval(timer))
</script>
