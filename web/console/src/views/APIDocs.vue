<template>
  <el-card shadow="never" :body-style="{ padding: 0 }">
    <div id="swagger-ui"></div>
  </el-card>
</template>

<script setup>
import { onMounted } from 'vue'
import SwaggerUI from 'swagger-ui-dist/swagger-ui-bundle.js'
import 'swagger-ui-dist/swagger-ui.css'

onMounted(() => {
  SwaggerUI({ url: '/openapi.json', dom_id: '#swagger-ui', docExpansion: 'list', defaultModelsExpandDepth: -1 })
})
</script>

<style>
#swagger-ui .topbar { display: none; }
#swagger-ui .swagger-ui { background: #fff; }
</style>
