<template>
  <div style="display:flex;gap:16px;align-items:flex-start">
    <el-card shadow="never" class="km-set-nav" :body-style="{ padding: '8px' }">
      <div v-for="t in tabs" :key="t.id" class="item" :class="{ on: tab === t.id }" @click="tab = t.id">
        <span>{{ t.icon }} {{ t.name }}</span>
        <el-tag v-if="t.pro" size="small" effect="plain" type="warning" class="km-tag" style="margin-left:auto">PRO</el-tag>
      </div>
    </el-card>

    <div style="flex:1;min-width:0">
      <el-alert type="info" :closable="false" show-icon style="margin-bottom:14px"
                title="系统设置保存即发布为新配置版本并热生效（与站点配置同一版本库，可回滚）" />

      <!-- ① 通用 -->
      <template v-if="tab === 'general'">
        <!-- 管理界面端口（在线更换：写 console.env + 自动重启，独立于配置发布流程） -->
        <el-card v-if="portInfo" shadow="never" style="margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
            <div class="km-title" style="margin:0">管理界面端口</div>
            <el-tag size="small" effect="plain" class="km-mono">当前 {{ portInfo.port }}</el-tag>
            <div style="flex:1"></div>
            <el-input-number v-model="portForm.port" :min="1" :max="65535" :controls="false" size="small"
                             :disabled="!portInfo.changeable || !can('admin')" placeholder="新端口"
                             class="km-mono" style="width:120px" />
            <el-button size="small" type="primary" :disabled="!portInfo.changeable || !can('admin')"
                       @click="openPortDlg">更换端口</el-button>
          </div>
          <div class="km-dim" style="font-size:12px;margin-top:8px;line-height:1.8">
            控制台端口由 systemd 单元从数据目录 console.env 读取，更换后服务自动重启生效（约 30 秒），数据面业务监听不受影响；防火墙需同步放行新端口。
          </div>
          <el-alert v-if="portResult" type="success" :closable="false" show-icon style="margin-top:12px"
                    :title="`端口变更已提交，服务重启中（约 ${portResult.seconds} 秒）`"
                    :description="`重启完成后请用新地址访问：${portResult.url} —— 当前标签页将失联；若超时未恢复，请按部署文档「控制台端口更换与失联恢复」手工恢复。`" />
        </el-card>

        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">功能开关</div>
          <el-form label-width="200px" label-position="left">
            <el-form-item label="请求快照捕获">
              <el-switch v-model="f.capture_requests" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">审计事件附带脱敏请求头/body 快样（隐私敏感）</span>
            </el-form-item>
            <el-form-item label="API 资产学习">
              <el-switch v-model="f.api_assets_enabled" />
            </el-form-item>
            <el-form-item label="风险引擎">
              <el-switch v-model="f.risks_enabled" />
            </el-form-item>
            <el-form-item label="匿名安装统计">
              <el-switch v-model="f.telemetry_enabled" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">默认关。开启后仅上报随机安装 ID、软件版本、操作系统架构与安装方式；不采集主机名、用户名、内网 IP 或任何业务数据；支持 DO_NOT_TRACK 环境变量一键关闭；连续 3 次无法连接统计服务会自动停止上报。保存并发布后生效。</span>
            </el-form-item>
        <el-form-item label="Prometheus /metrics 端点">
          <el-switch v-model="f.metrics_enabled" />
          <span class="km-dim" style="margin-left:10px;font-size:12px">可选指标端点（文本格式，控制台认证内；默认关，热生效）</span>
          <template v-if="f.metrics_enabled">
            <el-form-item label="外发推送目标">
              <div style="width:100%">
              <el-input v-model="f.metrics_push_url" placeholder="http://pushgateway:9091/metrics/job/kingmoat（留空 = 不推送，仅拉取）" class="km-mono" style="margin-bottom:6px" />
              <div style="display:flex;gap:8px;align-items:center">
                <span class="km-dim" style="font-size:12px">间隔</span>
                <el-input-number v-model="f.metrics_push_interval" :min="5" :max="3600" size="small" style="width:110px" />
                <span class="km-dim" style="font-size:12px">秒 · Bearer Token</span>
                <el-input v-model="f.metrics_push_token" placeholder="可选" class="km-mono" style="width:200px" show-password />
              </div>
              <div class="km-dim" style="font-size:12px;margin-top:4px">开启后按间隔将完整 /metrics 文本 POST 到目标（如 Pushgateway）；推送目标变更需重启服务生效</div>
              </div>
            </el-form-item>
          </template>
        </el-form-item>
          </el-form>
        </el-card>
        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">审计日志保留与查询治理</div>
          <el-form label-width="200px" label-position="left">
            <el-form-item label="审计事件保留天数">
              <el-input-number v-model="f.audit_retention_days" :min="1" :max="365" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">本机活动库仅保留 N 天（默认 7；保存后需重启服务生效）</span>
            </el-form-item>
            <el-form-item label="归档快照保留天数">
              <el-input-number v-model="f.archive_retention_days" :min="1" :max="3650" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">每日 gzip 快照保留 N 天（默认 30；保存后需重启服务生效）</span>
            </el-form-item>
            <el-form-item label="紧急降级（停止日志查询）">
              <el-switch v-model="f.query_degraded" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">开启后控制台历史/趋势查询立即降级，转发不受影响（热生效）</span>
            </el-form-item>
          </el-form>
          <el-alert type="warning" :closable="false" show-icon style="margin-top:6px"
                    title="保留期越长，本机日志库越大、控制台检索越慢，并可能挤占转发资源"
                    description="建议保持较短保留期，长期留存请启用「审计日志外发」。日志查询运行在独立只读通道，受并发上限与超时限制；攻击风暴等紧急情况可打开上方降级开关一键停止查询。" />
        </el-card>

        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">AI 助手</div>
          <el-form label-width="140px" label-position="left">
            <el-form-item label="启用">
              <el-switch v-model="f.ai_enabled" />
            </el-form-item>
            <template v-if="f.ai_enabled">
              <el-form-item label="服务商模板">
                <el-select v-model="f.ai_template" style="width:260px" @change="onTemplate">
                  <el-option v-for="tp in templates" :key="tp.id" :label="tp.name" :value="tp.id" />
                </el-select>
              </el-form-item>
              <el-form-item label="Base URL"><el-input v-model="f.ai_base" placeholder="https://api.openai.com/v1" class="km-mono" style="width:420px" /></el-form-item>
              <el-form-item label="模型"><el-input v-model="f.ai_model" placeholder="gpt-4o-mini" style="width:260px" /></el-form-item>
              <el-form-item label="API Key">
                <div style="display:flex;gap:8px;align-items:center;width:100%;flex-wrap:wrap">
                  <el-input v-model="aiKeyInput" type="password" show-password autocomplete="new-password"
                            placeholder="粘贴 Key 后保存入库，保存后不可再查看" class="km-mono" style="width:300px" />
                  <el-button size="small" type="primary" :disabled="!can('admin')" :loading="aiKeySaving" @click="saveAIKey">保存 Key</el-button>
                  <el-button size="small" type="danger" plain :disabled="!can('admin') || aiKeySaving || aiKeySource !== 'stored'" @click="clearAIKey">清除</el-button>
                  <el-tag size="small" effect="plain" :type="keySourceTag" class="km-tag">{{ keySourceLabel }}</el-tag>
                </div>
                <span class="km-dim" style="margin-left:10px;font-size:12px">存入数据库（argon2id 哈希 + KEK 加密），保存后不可再查看；优先于环境变量</span>
              </el-form-item>
              <el-form-item label="温度">
                <el-slider v-model="f.ai_temperature" :min="0" :max="2" :step="0.1" show-input style="width:320px" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">默认 0.2；越高越发散</span>
              </el-form-item>
              <el-form-item label="超时（秒）">
                <el-input-number v-model="f.ai_timeout" :min="10" :max="600" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">单次请求超时，默认 120</span>
              </el-form-item>
              <el-form-item label="输出上限">
                <el-input-number v-model="f.ai_max_tokens" :min="256" :max="1000000" :step="1024" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">单次回答的最大 tokens，默认 4096</span>
              </el-form-item>
              <el-form-item label="系统提示词">
                <el-input v-model="f.ai_sysprompt" type="textarea" :rows="4" spellcheck="false"
                          placeholder="留空使用内置只读分析师人设；自定义后覆盖默认人设" />
              </el-form-item>
              <el-form-item label="上下文窗口">
                <el-input-number v-model="f.ai_ctx_tokens" :min="0" :max="10000000" :step="1000" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">tokens，0 = 不限制；超限自动压缩历史</span>
              </el-form-item>
              <el-form-item label="压缩保留轮数">
                <el-input-number v-model="f.ai_keep_turns" :min="1" :max="50" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">压缩时保留最近 N 轮原文</span>
              </el-form-item>
            <el-form-item label="历史保留（天)">
              <el-input-number v-model="f.ai_history_days" :min="0" :max="3650" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">超过 N 天的 AI 会话自动清理（0 = 永久保留）</span>
            </el-form-item>
            <el-form-item label="出站脱敏">
              <el-switch v-model="f.ai_sanitize" />
              <el-tooltip content="发给大模型的攻击上下文/工具结果自动掩码 IP/主机/凭据，控制台展示自动还原" placement="top">
                <el-icon style="margin-left:8px;vertical-align:middle;color:var(--km-txt-3)"><QuestionFilled /></el-icon>
              </el-tooltip>
              <span class="km-dim" style="margin-left:10px;font-size:12px">默认开启，建议保持</span>
            </el-form-item>
            <el-form-item label="AI 日报">
              <el-switch v-model="f.ai_analysis" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">定时生成攻击态势报告并投递（报告留存于 AI 报告列表）</span>
            </el-form-item>
            <template v-if="f.ai_analysis">
              <el-form-item label="执行时间">
                <el-time-picker v-model="f.ai_report_time" value-format="HH:mm" format="HH:mm" placeholder="选择执行时间" style="width:140px" />
              </el-form-item>
              <el-form-item label="重复">
                <el-checkbox-group v-model="f.ai_report_days">
                  <el-checkbox :value="1">周一</el-checkbox>
                  <el-checkbox :value="2">周二</el-checkbox>
                  <el-checkbox :value="3">周三</el-checkbox>
                  <el-checkbox :value="4">周四</el-checkbox>
                  <el-checkbox :value="5">周五</el-checkbox>
                  <el-checkbox :value="6">周六</el-checkbox>
                  <el-checkbox :value="0">周日</el-checkbox>
                </el-checkbox-group>
              </el-form-item>
              <el-form-item label="单日 Token 限额（万）">
                <el-input-number v-model="f.ai_report_tokens_wan" :min="1" :max="1000" :step="1" />
                <span class="km-dim" style="margin-left:10px;font-size:12px">超出当日限额后报告自动暂停，次日恢复</span>
              </el-form-item>
              <el-form-item label="外发渠道">
                <el-radio-group v-model="f.ai_report_channel">
                  <el-radio-button value="webhook">Webhook</el-radio-button>
                  <el-radio-button value="email">邮箱</el-radio-button>
                </el-radio-group>
              </el-form-item>
              <el-form-item v-if="f.ai_report_channel === 'webhook'" label="Webhook URL">
                <el-input v-model="f.ai_report_webhook" placeholder="https://hooks.example.com/kingmoat" class="km-mono" style="width:420px" />
              </el-form-item>
              <template v-else>
                <el-form-item label="收件地址">
                  <el-input v-model="f.ai_report_email" placeholder="ops@corp.com, sec@corp.com" class="km-mono" style="width:420px" />
                  <div class="km-dim" style="font-size:12px;width:100%;margin-top:4px">多个地址用英文逗号分隔；邮箱渠道需先在「告警与通知」配置 SMTP</div>
                </el-form-item>
              </template>
            </template>
            </template>
          </el-form>
        </el-card>
</template>

      <!-- ② 日志外发 -->
      <template v-if="tab === 'logship'">
        <el-card shadow="never" style="margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:10px">
            <div class="km-title" style="margin:0">审计日志外发（log_shipper）</div>
            <el-button size="small" style="margin-left:auto" :loading="testing" @click="testShip">
              <el-icon><Promotion /></el-icon>&nbsp;发送测试事件
            </el-button>
          </div>
          <div v-if="testResult" style="margin-top:8px">
            <el-alert :type="testResult.ok ? 'success' : 'error'" :closable="false" show-icon
                      :title="testResult.detail" :description="testResult.latency_ms !== undefined ? `耗时 ${testResult.latency_ms}ms` : ''" />
          </div>
          <el-form label-width="140px" label-position="left" style="margin-top:12px">
            <el-form-item label="启用">
              <el-switch v-model="f.shipper_enabled" />
            </el-form-item>
            <template v-if="f.shipper_enabled">
              <el-form-item label="类型">
                <el-radio-group v-model="f.shipper_type">
                  <el-radio-button value="clickhouse">ClickHouse</el-radio-button>
                  <el-radio-button value="elasticsearch">Elasticsearch</el-radio-button>
                  <el-radio-button value="loki">Loki</el-radio-button>
                  <el-radio-button value="s3">S3 对象存储</el-radio-button>
                  <el-radio-button value="kafka">Kafka</el-radio-button>
                  <el-radio-button value="syslog">Syslog</el-radio-button>
                </el-radio-group>
              </el-form-item>
              <template v-if="!['s3', 'kafka'].includes(f.shipper_type)">
                <el-form-item label="地址">
                  <el-input v-model="f.shipper_url" :placeholder="urlHint" class="km-mono" style="width:420px" />
                </el-form-item>
                <el-form-item label="表 / 索引前缀">
                  <el-input v-model="f.shipper_index" style="width:260px" placeholder="kingmoat" />
                </el-form-item>
                <template v-if="['clickhouse', 'elasticsearch', 'loki'].includes(f.shipper_type)">
                  <el-form-item label="认证用户名">
                    <el-input v-model="f.shipper_user" class="km-mono" style="width:260px" placeholder="无认证则留空" autocomplete="off" />
                  </el-form-item>
                  <el-form-item label="认证密码">
                    <el-input v-model="f.shipper_pass" type="password" show-password class="km-mono" style="width:260px" placeholder="无认证则留空" autocomplete="new-password" />
                  </el-form-item>
                </template>
              </template>
              <template v-if="f.shipper_type === 'syslog'">
                <el-form-item label="消息格式">
                  <el-radio-group v-model="f.shipper_sys_format">
                    <el-radio-button value="rfc5424">RFC 5424</el-radio-button>
                    <el-radio-button value="rfc3164">RFC 3164 (BSD)</el-radio-button>
                  </el-radio-group>
                </el-form-item>
                <el-form-item label="主机名">
                  <el-input v-model="f.shipper_sys_hostname" placeholder="默认本机主机名" style="width:260px" />
                </el-form-item>
              </template>
              <template v-else-if="f.shipper_type === 's3'">
                <el-form-item label="Endpoint"><el-input v-model="f.s3_endpoint" placeholder="minio.internal:9000（不带协议）" class="km-mono" style="width:420px" /></el-form-item>
                <el-form-item label="Bucket"><el-input v-model="f.s3_bucket" placeholder="kingmoat-logs" style="width:260px" /></el-form-item>
                <el-form-item label="对象前缀"><el-input v-model="f.s3_prefix" placeholder="kingmoat" style="width:260px" /></el-form-item>
                <el-form-item label="AccessKey"><el-input v-model="f.s3_ak" class="km-mono" style="width:260px" /></el-form-item>
                <el-form-item label="SecretKey"><el-input v-model="f.s3_sk" type="password" show-password class="km-mono" style="width:260px" /></el-form-item>
                <el-form-item label="使用 HTTPS"><el-switch v-model="f.s3_ssl" /></el-form-item>
              </template>
              <template v-else-if="f.shipper_type === 'kafka'">
                <el-form-item label="Bootstrap 服务器">
                  <el-input v-model="f.shipper_kafka_brokers" type="textarea" :rows="3" class="km-mono"
                            placeholder="每行一个或逗号分隔：&#10;kafka-1.internal:9092&#10;kafka-2.internal:9092" style="width:420px" />
                </el-form-item>
                <el-form-item label="Topic">
                  <el-input v-model="f.shipper_kafka_topic" placeholder="kingmoat-audit" class="km-mono" style="width:260px" />
                </el-form-item>
                <el-form-item label="TLS 加密">
                  <el-switch v-model="f.shipper_kafka_tls" />
                  <span class="km-dim" style="margin-left:10px;font-size:12px">内网自签证书场景默认不校验证书</span>
                </el-form-item>
                <el-form-item v-if="f.shipper_kafka_tls" label="跳过 TLS 证书校验">
                  <el-switch v-model="f.shipper_kafka_tls_skip" />
                  <span class="km-dim" style="margin-left:10px;font-size:12px">内网自签证书保持开启；关闭后将校验 broker 证书</span>
                </el-form-item>
                <el-form-item label="SASL 认证">
                  <el-select v-model="f.shipper_kafka_sasl" style="width:220px">
                    <el-option value="none" label="无认证" />
                    <el-option value="plain" label="PLAIN" />
                    <el-option value="scram-sha256" label="SCRAM-SHA-256" />
                  </el-select>
                </el-form-item>
                <template v-if="f.shipper_kafka_sasl !== 'none'">
                  <el-form-item label="认证用户名">
                    <el-input v-model="f.shipper_user" class="km-mono" style="width:260px" autocomplete="off" />
                  </el-form-item>
                  <el-form-item label="认证密码">
                    <el-input v-model="f.shipper_pass" type="password" show-password class="km-mono" style="width:260px" autocomplete="new-password" />
                  </el-form-item>
                </template>
                <div class="km-dim" style="font-size:12px;padding-left:140px">日志外发配置保存后需重启服务生效</div>
              </template>
            </template>
          </el-form>
        </el-card>

        <el-card shadow="never">
          <div class="km-title">全量访问日志管道（access_log）</div>
          <el-form label-width="140px" label-position="left">
            <el-form-item label="启用">
              <el-switch v-model="f.access_enabled" />
            </el-form-item>
            <template v-if="f.access_enabled">
              <el-form-item label="类型">
                <el-radio-group v-model="f.access_type">
                  <el-radio-button value="clickhouse">ClickHouse</el-radio-button>
                  <el-radio-button value="elasticsearch">Elasticsearch</el-radio-button>
                  <el-radio-button value="loki">Loki</el-radio-button>
                  <el-radio-button value="s3">S3 对象存储</el-radio-button>
                  <el-radio-button value="syslog">Syslog</el-radio-button>
                </el-radio-group>
              </el-form-item>
              <template v-if="f.access_type !== 's3'">
                <el-form-item label="地址">
                  <el-input v-model="f.access_url" :placeholder="accessUrlHint" class="km-mono" style="width:420px" />
                </el-form-item>
                <el-form-item label="表 / 索引前缀">
                  <el-input v-model="f.access_index" style="width:260px" placeholder="kingmoat_access" />
                </el-form-item>
                <template v-if="['clickhouse', 'elasticsearch', 'loki'].includes(f.access_type)">
                  <el-form-item label="认证用户名">
                    <el-input v-model="f.access_user" class="km-mono" style="width:260px" placeholder="无认证则留空" autocomplete="off" />
                  </el-form-item>
                  <el-form-item label="认证密码">
                    <el-input v-model="f.access_pass" type="password" show-password class="km-mono" style="width:260px" placeholder="无认证则留空" autocomplete="new-password" />
                  </el-form-item>
                </template>
              </template>
              <template v-if="f.access_type === 'syslog'">
                <el-form-item label="消息格式">
                  <el-radio-group v-model="f.access_sys_format">
                    <el-radio-button value="rfc5424">RFC 5424</el-radio-button>
                    <el-radio-button value="rfc3164">RFC 3164 (BSD)</el-radio-button>
                  </el-radio-group>
                </el-form-item>
                <el-form-item label="主机名">
                  <el-input v-model="f.access_sys_hostname" placeholder="默认本机主机名" style="width:260px" />
                </el-form-item>
              </template>
              <template v-else-if="f.access_type === 's3'">
                <el-form-item label="Endpoint"><el-input v-model="f.access_s3_endpoint" placeholder="minio.internal:9000" class="km-mono" style="width:420px" /></el-form-item>
                <el-form-item label="Bucket"><el-input v-model="f.access_s3_bucket" placeholder="kingmoat-logs" style="width:260px" /></el-form-item>
                <el-form-item label="对象前缀"><el-input v-model="f.access_s3_prefix" placeholder="kingmoat" style="width:260px" /></el-form-item>
                <el-form-item label="AccessKey"><el-input v-model="f.access_s3_ak" class="km-mono" style="width:260px" /></el-form-item>
                <el-form-item label="SecretKey"><el-input v-model="f.access_s3_sk" type="password" show-password class="km-mono" style="width:260px" /></el-form-item>
                <el-form-item label="使用 HTTPS"><el-switch v-model="f.access_s3_ssl" /></el-form-item>
              </template>
              <el-form-item label="采样率 %">
                <el-slider v-model="f.access_sample" :min="1" :max="100" show-input style="width:320px" />
              </el-form-item>
            </template>
          </el-form>
        </el-card>
      </template>

      <!-- ④ 安全设置（迁回：密码策略 / 会话超时 / 管理面板访问限制） -->
      <template v-if="tab === 'security'">
        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">密码与会话策略</div>
          <el-form label-width="190px" label-position="left">
            <el-form-item label="密码最小长度">
              <el-input-number v-model="f.sec_min_len" :min="6" :max="64" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">创建用户与修改密码时生效（默认 8；已有密码不受影响）</span>
            </el-form-item>
            <el-form-item label="密码复杂度">
              <el-switch v-model="f.sec_complexity" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">需同时包含大写 / 小写 / 数字</span>
            </el-form-item>
            <el-form-item label="密码有效期（天）">
              <el-input-number v-model="f.sec_max_age" :min="0" :max="3650" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">超期登录将被拒绝并提示重置（0 = 不启用）</span>
            </el-form-item>
            <el-form-item label="密码历史次数">
              <el-input-number v-model="f.sec_pw_history" :min="0" :max="24" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">改密时不可与最近 N 次用过的密码相同（0 = 不启用）</span>
            </el-form-item>
            <el-form-item label="会话空闲超时（分钟）">
              <el-input-number v-model="f.sec_session" :min="0" :max="10080" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">登录态有效期，保存后需重启服务生效（0 = 默认 12 小时）</span>
            </el-form-item>
            <el-form-item label="登录错误锁定">
              <el-input-number v-model="f.sec_login_max" :min="3" :max="100" style="width:130px" />
              <span class="km-dim" style="margin:0 6px;font-size:12px">次失败后锁定</span>
              <el-input-number v-model="f.sec_lockout_min" :min="1" :max="1440" style="width:120px" />
              <span class="km-dim" style="margin-left:6px;font-size:12px">分钟（同一来源 IP，滑动窗口；默认 10 次 / 15 分钟）</span>
            </el-form-item>
          </el-form>
        </el-card>
        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">管理面板访问限制</div>
          <el-form label-width="140px" label-position="left">
            <el-form-item label="允许的来源 IP">
              <div style="width:100%">
                <div v-for="(ip, i) in f.console_ips" :key="i" style="display:flex;gap:8px;margin-bottom:6px">
                  <el-input v-model="f.console_ips[i]" placeholder="IP/CIDR，如 10.0.0.0/8" class="km-mono" />
                  <el-button link type="danger" @click="f.console_ips.splice(i, 1)"><el-icon><Delete /></el-icon></el-button>
                </div>
                <el-button size="small" @click="f.console_ips.push('')"><el-icon><Plus /></el-icon>&nbsp;新增</el-button>
                
              </div>
            </el-form-item>
          </el-form>
        </el-card>
        <el-card shadow="never">
          <div class="km-title">拦截页面定制（阻断页）</div>
          <el-form label-width="110px" label-position="left">
            <el-form-item label="页面标题">
              <el-input v-model="f.bp_title" placeholder="请求被拦截 · Blocked by KingMoat" style="width:420px" />
            </el-form-item>
            <el-form-item label="说明文字">
              <el-input v-model="f.bp_message" type="textarea" :rows="2" style="width:420px"
                        placeholder="该请求触发了安全防护规则，已被拒绝访问。" />
            </el-form-item>
            <el-form-item label="页脚">
              <el-input v-model="f.bp_footer" placeholder="KingMoat WAF — 固若金汤，御攻于无形" style="width:420px" />
            </el-form-item>
            <el-form-item label="自定义 HTML">
              <div style="width:100%">
                <el-input v-model="f.bp_html" type="textarea" :rows="8" class="km-mono" spellcheck="false"
                          placeholder="留空使用内置拦截页；填写完整 HTML（≤256KB）将整体替换内置页面" />
                <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:6px;align-items:center">
                  <span class="km-dim" style="font-size:12px">可用变量（点击插入）：</span>
                  <div v-for="v in bpVars" :key="v" class="km-chip km-mono" style="padding:2px 8px;font-size:11px" @click="insertBpVar(v)">{{ v }}</div>
                </div>
                <div class="km-dim" style="font-size:12px;margin-top:6px">
                  引擎响应时替换为请求上下文；保存时服务端会拒绝包含 script / 内联事件 / javascript: 的页面（防存储型 XSS）
                </div>
                <div style="margin-top:10px">
                  <div class="km-dim" style="font-size:12px;margin-bottom:6px">实时预览（变量已替换为示例值）</div>
                  <iframe v-if="bpPreview" :srcdoc="bpPreview" sandbox="allow-forms"
                          style="width:100%;height:300px;border:1px solid var(--km-line);border-radius:8px;background:#fff" />
                </div>
              </div>
            </el-form-item>
          </el-form>
        </el-card>
      </template>

      <!-- ⑤ 告警与通知 -->
      <template v-if="tab === 'alerts'">
        <el-card shadow="never" style="margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
            <div class="km-title" style="margin:0">告警引擎</div>
            <el-switch v-model="f.alerts_enabled" style="margin-left:auto" />
          </div>
          <el-form label-width="150px" label-position="left">
            <el-form-item label="评估间隔（秒）">
              <el-input-number v-model="f.alerts_interval" :min="10" :max="3600" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">默认 60；同时是 CPU/内存规则的 1 分钟采样窗</span>
            </el-form-item>
            <el-form-item label="告警冷却（分钟）">
              <el-input-number v-model="f.alerts_cooldown" :min="1" :max="1440" />
              <span class="km-dim" style="margin-left:10px;font-size:12px">同一规则两次通知的最小间隔（默认 10）</span>
            </el-form-item>
            <el-form-item label="Webhook 通知">
              <el-switch v-model="f.alerts_webhook" />
            </el-form-item>
            <el-form-item label="邮件通知">
              <el-switch v-model="f.alerts_email" />
            </el-form-item>
          </el-form>
        </el-card>

        <el-card shadow="never" style="margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">
            <div class="km-title" style="margin:0">告警阈值（全部可调）</div>
          </div>
          <div class="km-set-row" v-for="r in alertRuleDefs" :key="r.key">
            <div class="grow">
              <div class="set-name">{{ r.name }}</div>
              <div class="set-desc">{{ r.desc }}</div>
            </div>
            <el-switch v-model="f.alert_rules[r.key].enabled" />
            <el-input-number v-model="f.alert_rules[r.key].threshold" :min="r.min" :max="r.max" size="small" style="width:130px" />
            <span class="km-muted" style="font-size:12px;width:60px">{{ r.unit }}</span>
            <template v-if="r.window">
              <span class="km-muted" style="font-size:12px">持续</span>
              <el-input-number v-model="f.alert_rules[r.key].window_sec" :min="10" :max="3600" size="small" style="width:100px" />
              <span class="km-muted" style="font-size:12px">秒</span>
            </template>
          </div>
        </el-card>

        <el-card shadow="never" style="margin-bottom:16px">
          <div class="km-title">通知渠道 · Webhook</div>
          <el-form label-width="130px" label-position="left">
            <el-form-item label="推送地址">
              <el-input v-model="f.webhook_url" placeholder="https://hooks.example.com/kingmoat" class="km-mono" style="width:100%" />
            </el-form-item>
            <el-form-item label="加签密钥">
              <el-input v-model="f.webhook_secret" placeholder="留空不加签；填写后每条通知带 X-KingMoat-Signature 头（HMAC-SHA256）" class="km-mono" style="width:100%" show-password />
            </el-form-item>
            <el-form-item label="关键词认证">
              <el-input v-model="f.webhook_keyword" placeholder="如 企业微信/钉钉机器人关键词；填写后通知 JSON 携带 keyword 字段" style="width:100%" />
            </el-form-item>
          </el-form>
        </el-card>

        <el-card shadow="never">
          <div class="km-title">通知渠道 · 邮件（SMTP）</div>
          <el-form label-width="130px" label-position="left">
            <el-form-item label="启用邮件通道">
              <el-switch v-model="f.email_enabled" />
            </el-form-item>
            <template v-if="f.email_enabled">
              <el-form-item label="SMTP 服务器">
                <div style="display:flex;gap:8px;align-items:center;width:100%">
                  <el-input v-model="f.email_host" placeholder="smtp.example.com" class="km-mono" style="flex:1" />
                  <el-input-number v-model="f.email_port" :min="1" :max="65535" size="small" style="width:110px" />
                  <el-switch v-model="f.email_ssl" active-text="SSL" />
                </div>
              </el-form-item>
              <el-form-item label="发件人">
                <el-input v-model="f.email_from" placeholder="waf@example.com" class="km-mono" style="width:100%" />
              </el-form-item>
              <el-form-item label="账号 / 密码">
                <div style="display:flex;gap:8px;width:100%">
                  <el-input v-model="f.email_user" placeholder="SMTP 用户名" class="km-mono" style="flex:1" />
                  <el-input v-model="f.email_pass" type="password" show-password placeholder="SMTP 密码" class="km-mono" style="flex:1" />
                </div>
              </el-form-item>
              <el-form-item label="收件人">
                <div style="width:100%">
                  <div v-for="(to, i) in f.email_to" :key="i" style="display:flex;gap:8px;margin-bottom:6px">
                    <el-input v-model="f.email_to[i]" placeholder="ops@example.com" class="km-mono" />
                    <el-button link type="danger" @click="f.email_to.splice(i, 1)"><el-icon><Delete /></el-icon></el-button>
                  </div>
                  <el-button size="small" @click="f.email_to.push('')"><el-icon><Plus /></el-icon>&nbsp;新增收件人</el-button>
                </div>
              </el-form-item>
            </template>
          </el-form>
        </el-card>
      </template>

      <div style="text-align:right">
        <el-button type="primary" size="large" :loading="saving" :disabled="!can('operator')" @click="save">
          保存并发布（热生效）
        </el-button>
      </div>
    </div>

    <!-- 管理界面端口更换确认 -->
    <el-dialog v-model="portDlg" title="更换管理界面端口" width="540px" :close-on-click-modal="false">
      <el-alert type="warning" :closable="false" show-icon style="margin-bottom:14px"
                title="保存后服务将自动重启，约 30 秒内控制台不可访问" />
      <el-form label-width="90px" label-position="left">
        <el-form-item label="当前端口"><span class="km-mono">{{ portInfo?.port }}</span></el-form-item>
        <el-form-item label="新端口">
          <el-input-number v-model="portForm.port" :min="1" :max="65535" :controls="false" class="km-mono" style="width:160px" />
        </el-form-item>
      </el-form>
      <div class="km-dim" style="font-size:12px;line-height:1.9">
        重启完成后请用新地址访问：<span class="km-mono">{{ portPreviewUrl }}</span><br />
        当前浏览器标签页将随重启失联；若重启后无法访问，请登录服务器按部署文档「控制台端口更换与失联恢复」小节手工恢复（改回 console.env 后 systemctl restart kingmoat）。
      </div>
      <template #footer>
        <el-button @click="portDlg = false">取消</el-button>
        <el-button type="primary" :loading="portChanging" :disabled="!portForm.port || portForm.port === portInfo?.port" @click="submitPort">确认更换</el-button>
      </template>
    </el-dialog>

    <!-- OpenAPI 清单弹窗 -->
    
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, can, del, post, role } from '../api'

const tabs = [
  { id: 'general', name: '通用设置', icon: '⚙️' },
  { id: 'logship', name: '日志外发', icon: '📤' },
  { id: 'alerts', name: '告警与通知', icon: '🔔' },
  { id: 'security', name: '安全设置', icon: '🔒' },
]
const tab = ref('general')

const saving = ref(false)
const testing = ref(false)
const testResult = ref(null)

// 告警阈值规则定义(顺序即展示顺序;阈值区间为 UI 约束)
const alertRuleDefs = [
  { key: 'cpu', name: 'CPU 使用率过高', desc: 'CPU 使用率连续超过阈值', unit: '%', min: 1, max: 100, window: true },
  { key: 'mem', name: '内存使用率过高', desc: '内存使用率连续超过阈值', unit: '%', min: 1, max: 100, window: true },
  { key: 'disk', name: '磁盘使用率过高', desc: '数据盘使用率超过阈值(瞬时)', unit: '%', min: 1, max: 100 },
  { key: 'requests', name: '出现大量 Web 请求', desc: '1 分钟内 Web 请求超过阈值', unit: '次/分', min: 10, max: 10000000 },
  { key: 'attacks', name: '出现大量 Web 攻击', desc: '1 分钟内 Web 攻击事件超过阈值', unit: '次/分', min: 10, max: 10000000 },
  { key: 'blocked', name: '请求大量被拦截', desc: '1 分钟内拦截请求超过阈值', unit: '次/分', min: 10, max: 10000000 },
  { key: 'top_ip', name: '攻击 IP 排名告警', desc: '1 小时内单 IP 攻击次数超过阈值', unit: '次/时', min: 10, max: 10000000 },
  { key: 'top_target', name: '攻击目标排名告警', desc: '1 小时内单目标被攻击超过阈值', unit: '次/时', min: 10, max: 10000000 },
]

const f = reactive({
  capture_requests: false,
  api_assets_enabled: false,
  risks_enabled: false,
  audit_retention_days: 7,
  archive_retention_days: 30,
  query_degraded: false,
  metrics_enabled: false,
  metrics_push_url: '', metrics_push_interval: 30, metrics_push_token: '',
  // 告警与通知
  alerts_enabled: false, alerts_interval: 60, alerts_cooldown: 10,
  alerts_webhook: false, alerts_email: false,
  webhook_url: '',
  alert_rules: {
    cpu: { enabled: true, threshold: 80, window_sec: 60 }, mem: { enabled: true, threshold: 80, window_sec: 60 },
    disk: { enabled: true, threshold: 80 }, requests: { enabled: true, threshold: 20000 },
    attacks: { enabled: true, threshold: 10000 }, blocked: { enabled: true, threshold: 10000 },
    top_ip: { enabled: true, threshold: 20000 }, top_target: { enabled: true, threshold: 20000 },
  },
  email_enabled: false, email_host: '', email_port: 465, email_from: '',
  email_user: '', email_pass: '', email_ssl: true, email_to: [],
  // 安全设置
  sec_min_len: 8, sec_complexity: false, sec_max_age: 0, sec_session: 0,
  telemetry_enabled: false,
  sec_pw_history: 0, sec_login_max: 10, sec_lockout_min: 15,
  bp_title: '', bp_message: '', bp_footer: '', bp_html: '',
  shipper_enabled: false, shipper_type: 'clickhouse', shipper_url: '', shipper_index: 'kingmoat',
  shipper_sys_format: 'rfc5424', shipper_sys_hostname: '',
  shipper_kafka_brokers: '', shipper_kafka_topic: '', shipper_kafka_tls: false, shipper_kafka_tls_skip: true, shipper_kafka_sasl: 'none',
  access_enabled: false, access_type: 'clickhouse', access_url: '', access_index: 'kingmoat_access', access_sample: 100,
  access_sys_format: 'rfc5424', access_sys_hostname: '',
  console_ips: [],
  ai_enabled: false, ai_template: 'openai', ai_base: '', ai_model: '',
  ai_max_tokens: 4096, ai_ctx_tokens: 0, ai_keep_turns: 4, ai_temperature: 0.2, ai_timeout: 120, ai_sysprompt: '',
  ai_history_days: 0,
  ai_sanitize: true,
  ai_analysis: false, ai_report_time: '08:00', ai_report_days: [1, 2, 3, 4, 5, 6, 0],
  ai_report_tokens_wan: 20, ai_report_channel: 'webhook', ai_report_webhook: '', ai_report_email: '',
  s3_endpoint: '', s3_bucket: '', s3_prefix: 'kingmoat', s3_ak: '', s3_sk: '', s3_ssl: false,
  access_s3_endpoint: '', access_s3_bucket: '', access_s3_prefix: 'kingmoat', access_s3_ak: '', access_s3_sk: '', access_s3_ssl: false
})

// AI Key 存库：状态徽标 + 保存/清除（仅 admin；密钥只在请求体内，不回显）
const aiKeyInput = ref('')
const aiKeySaving = ref(false)
const aiKeySource = ref('')
const keySourceLabel = computed(() => ({ stored: '已存库', env: '环境变量', none: '未配置' }[aiKeySource.value] || '未启用'))
const keySourceTag = computed(() => ({ stored: 'success', env: 'warning', none: 'info' }[aiKeySource.value] || 'info'))

async function refreshAIKeyStatus() {
  try {
    const d = await api('/api/ai/config')
    aiKeySource.value = d.enabled ? (d.key_source || 'none') : ''
  } catch (e) { aiKeySource.value = '' }
}

async function saveAIKey() {
  const key = (aiKeyInput.value || '').trim()
  if (!key) return ElMessage.warning('请先粘贴 API Key')
  aiKeySaving.value = true
  try {
    await post('/api/ai/key', { key })
    ElMessage.success('API Key 已存库并热生效')
    aiKeyInput.value = ''
    await refreshAIKeyStatus()
  } catch (e) {
    ElMessage.error('保存失败：' + e.message)
  } finally {
    aiKeySaving.value = false
  }
}

async function clearAIKey() {
  try {
    await ElMessageBox.confirm('清除后助手将回退到环境变量取 Key（若无则不可用）。确认清除已存库的 API Key？', '清除 API Key', { type: 'warning', confirmButtonText: '清除', cancelButtonText: '取消' })
  } catch (e) { return }
  aiKeySaving.value = true
  try {
    await del('/api/ai/key')
    ElMessage.success('已清除存库 API Key')
    await refreshAIKeyStatus()
  } catch (e) {
    ElMessage.error('清除失败：' + e.message)
  } finally {
    aiKeySaving.value = false
  }
}

const urlHint = computed(() =>
  ({ clickhouse: 'http://ch:8123', elasticsearch: 'http://es:9200', loki: 'http://loki:3100', syslog: 'udp://siem.internal:514', kafka: 'broker1:9092, broker2:9092' }[f.shipper_type] || ''))
const accessUrlHint = computed(() =>
  ({ clickhouse: 'http://ch:8123', elasticsearch: 'http://es:9200', loki: 'http://loki:3100', syslog: 'udp://siem.internal:514' }[f.access_type] || ''))

// ===== 管理界面端口（console.env + 自动重启，独立于配置发布流程）=====
const portInfo = ref(null)
const portDlg = ref(false)
const portChanging = ref(false)
const portForm = reactive({ port: null })
const portResult = ref(null)
let portCountdown = null

const portPreviewUrl = computed(() =>
  portForm.port ? `https://${location.hostname}:${portForm.port}` : '-')

async function loadConsolePort() {
  try { portInfo.value = await api('/api/settings/console-port') } catch (e) { portInfo.value = null }
}

function openPortDlg() {
  portForm.port = null
  portDlg.value = true
}

async function submitPort() {
  const p = Number(portForm.port)
  if (!Number.isInteger(p) || p < 1 || p > 65535) return ElMessage.error('端口需在 1-65535 之间')
  if (portInfo.value && p === portInfo.value.port) return ElMessage.error('新端口与当前端口相同')
  portChanging.value = true
  try {
    const r = await post('/api/settings/console-port', { port: p })
    // 提交成功即更新本地展示；服务即将重启，约 30 秒后旧地址失联
    portInfo.value = { ...(portInfo.value || {}), port: p }
    portResult.value = { port: p, url: `https://${location.hostname}:${p}`, seconds: 30 }
    if (portCountdown) clearInterval(portCountdown)
    portCountdown = setInterval(() => {
      if (portResult.value && portResult.value.seconds > 0) portResult.value.seconds--
      else { clearInterval(portCountdown); portCountdown = null }
    }, 1000)
    portDlg.value = false
    ElMessage.success(r.message || '端口变更已提交，服务重启中')
  } catch (e) {
    ElMessage.error('端口变更失败：' + e.message) // 占用/冲突/非法：后端中文错误直接展示
  } finally { portChanging.value = false }
}

// 拦截页定制：可用变量 + 实时预览（示例值替换 + iframe sandbox）
const bpVars = ['{{request_id}}', '{{rule_id}}', '{{reason}}', '{{client_ip}}', '{{method}}', '{{host}}', '{{url}}', '{{ua}}', '{{timestamp}}']
const bpPreview = computed(() => {
  if (!f.bp_html) return ''
  const sample = {
    request_id: 'tr-4f8a2c1b', rule_id: 'crs/942100', reason: 'SQL 注入特征',
    client_ip: '203.0.113.7', method: 'GET', host: 'portal.example.cn',
    url: '/api/user?id=1', ua: 'Mozilla/5.0 (X11; Linux x86_64)', timestamp: new Date().toLocaleString(),
  }
  return f.bp_html.replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (m, k) => (sample[k] !== undefined ? sample[k] : ''))
})

function insertBpVar(v) {
  f.bp_html = (f.bp_html || '') + v
}

const rbac = [
  { perm: '查看仪表盘 / 日志 / 报表', admin: true, operator: true, auditor: true },
  { perm: '站点防护配置（保存并发布）', admin: true, operator: true, auditor: false },
  { perm: '策略管理（规则 / 名单 / SecLang）', admin: true, operator: true, auditor: false },
  { perm: '攻击日志一键加白', admin: true, operator: true, auditor: false },
  { perm: '证书上传 / 站点证书管理', admin: true, operator: true, auditor: false },
  { perm: '系统设置 / 用户管理', admin: true, operator: false, auditor: false },
  { perm: 'AI 助手（只读分析）', admin: true, operator: true, auditor: true, opNote: '只读', audNote: '只读' },
]

async function load() {
  const d = await api('/api/config')
  const c = d.config
  f.capture_requests = !!c.capture_requests
  f.telemetry_enabled = !!(c.telemetry && c.telemetry.enabled)
  f.api_assets_enabled = !!c.api_assets?.enabled
  f.risks_enabled = !!c.risks?.enabled
  f.audit_retention_days = c.audit_retention_days > 0 ? c.audit_retention_days : 7
  f.archive_retention_days = c.audit_archive?.retention_days > 0 ? c.audit_archive.retention_days : 30
  f.query_degraded = !!c.audit_query?.degraded
  f.metrics_enabled = !!c.metrics?.enabled
  f.metrics_push_url = c.metrics?.push?.url || ''
  f.metrics_push_interval = c.metrics?.push?.interval_sec || 30
  f.metrics_push_token = c.metrics?.push?.bearer_token || ''
  f.shipper_enabled = !!c.log_shipper
  f.shipper_type = c.log_shipper?.type || 'clickhouse'
  f.shipper_url = c.log_shipper?.url || ''
  f.shipper_index = c.log_shipper?.index || 'kingmoat'
  f.shipper_sys_format = c.log_shipper?.syslog?.format || 'rfc5424'
  f.shipper_sys_hostname = c.log_shipper?.syslog?.hostname || ''
  // S3 字段为 ShipperSettings 顶层（endpoint/bucket/access_key/...）
  f.s3_endpoint = c.log_shipper?.endpoint || ''
  f.s3_bucket = c.log_shipper?.bucket || ''
  f.s3_prefix = c.log_shipper?.prefix || 'kingmoat'
  f.s3_ak = c.log_shipper?.access_key || ''
  f.s3_sk = c.log_shipper?.secret_key || ''
  f.s3_ssl = !!c.log_shipper?.use_ssl
  f.shipper_kafka_brokers = (c.log_shipper?.brokers || []).join('\n')
  f.shipper_kafka_topic = c.log_shipper?.topic || ''
  f.shipper_kafka_tls = !!c.log_shipper?.use_tls
  f.shipper_kafka_tls_skip = c.log_shipper?.tls_skip_verify !== false
  f.shipper_kafka_sasl = c.log_shipper?.sasl || 'none'
  f.shipper_user = c.log_shipper?.username || ''
  f.shipper_pass = c.log_shipper?.password || ''
  f.access_enabled = !!c.access_log?.enabled
  f.access_type = c.access_log?.type || 'clickhouse'
  f.access_url = c.access_log?.url || ''
  f.access_index = c.access_log?.index || 'kingmoat_access'
  f.access_sys_format = c.access_log?.syslog?.format || 'rfc5424'
  f.access_sys_hostname = c.access_log?.syslog?.hostname || ''
  f.access_sample = c.access_log?.sample_pct || 100
  f.access_s3_endpoint = c.access_log?.endpoint || ''
  f.access_s3_bucket = c.access_log?.bucket || ''
  f.access_s3_prefix = c.access_log?.prefix || 'kingmoat'
  f.access_s3_ak = c.access_log?.access_key || ''
  f.access_s3_sk = c.access_log?.secret_key || ''
  f.access_s3_ssl = !!c.access_log?.use_ssl
  f.access_user = c.access_log?.username || ''
  f.access_pass = c.access_log?.password || ''
  f.webhook_enabled = !!c.webhook
  f.webhook_url = c.webhook?.url || ''
  f.webhook_secret = c.webhook?.secret || ''
  f.webhook_keyword = c.webhook?.keyword || ''
  // 告警与通知
  f.alerts_enabled = !!c.alerts?.enabled
  f.alerts_interval = c.alerts?.interval_sec || 60
  f.alerts_cooldown = c.alerts?.cooldown_min || 10
  f.alerts_webhook = !!c.alerts?.notify_webhook
  f.alerts_email = !!c.alerts?.notify_email
  const src = c.alerts?.rules || {}
  const defs = { cpu: 80, mem: 80, disk: 80, web_requests: 20000, web_attacks: 10000, blocked: 10000, top_attack_ip: 20000, top_target: 20000 }
  const keyMap = { cpu: 'cpu', mem: 'mem', disk: 'disk', requests: 'web_requests', attacks: 'web_attacks', blocked: 'blocked', top_ip: 'top_attack_ip', top_target: 'top_target' }
  for (const k of Object.keys(keyMap)) {
    const bk = keyMap[k]
    const r = src[bk]
    f.alert_rules[k] = r ? { enabled: !!r.enabled, threshold: r.threshold || defs[bk], window_sec: r.window_sec || 60 } : { enabled: true, threshold: defs[bk], window_sec: 60 }
  }
  // 邮件通道
  f.email_enabled = !!c.email?.enabled
  f.email_host = c.email?.host || ''
  f.email_port = c.email?.port || 465
  f.email_from = c.email?.from || ''
  f.email_user = c.email?.username || ''
  f.email_pass = c.email?.password || ''
  f.email_ssl = !!c.email?.ssl
  f.email_to = [...(c.email?.to || [])]
  // 安全设置(迁回)
  f.sec_min_len = c.security?.password_min_len || 8
  f.sec_complexity = !!c.security?.password_complexity
  f.sec_max_age = c.security?.password_max_age_days || 0
  f.sec_session = c.security?.session_timeout_min || 0
  f.sec_pw_history = c.security?.password_history_count || 0
  f.sec_login_max = c.security?.login_max_failures || 10
  f.sec_lockout_min = c.security?.login_lockout_min || 15
  f.console_ips = [...(c.console?.allowed_ips || [])]
  f.bp_title = c.block_page?.title || ''
  f.bp_message = c.block_page?.message || ''
  f.bp_footer = c.block_page?.footer || ''
  f.bp_html = c.block_page?.html || ''
  f.ai_enabled = !!c.ai?.enabled
  f.ai_template = c.ai?.provider?.template || 'openai'
  f.ai_base = c.ai?.provider?.base_url || ''
  f.ai_model = c.ai?.provider?.model || ''
  f.ai_max_tokens = c.ai?.provider?.max_tokens || 4096
  f.ai_temperature = c.ai?.provider?.temperature > 0 ? c.ai.provider.temperature : 0.2
  f.ai_timeout = c.ai?.provider?.timeout_sec || 120
  f.ai_sysprompt = c.ai?.system_prompt || ''
  f.ai_ctx_tokens = c.ai?.chat?.context_window_tokens || 0
  f.ai_keep_turns = c.ai?.chat?.keep_recent_turns || 4
  f.ai_history_days = c.ai?.chat?.history_retention_days || 0
  f.ai_sanitize = c.ai?.sanitize?.enabled !== false
  f.ai_analysis = !!c.ai?.analysis?.enabled
  f.ai_report_tokens_wan = Math.max(1, Math.round((c.ai?.analysis?.max_tokens_per_day || 200000) / 10000))
  const daily = (c.ai?.analysis?.schedules || []).find(s => s.kind === 'attack_summary_daily')
  f.ai_report_channel = daily?.channel === 'email' ? 'email' : 'webhook'
  f.ai_report_webhook = daily?.webhook || ''
  f.ai_report_email = daily?.email || ''
  if (daily?.cron) {
    const parsed = parseReportCron(daily.cron)
    if (parsed) {
      f.ai_report_time = parsed.time
      f.ai_report_days = parsed.days
    }
  } else {
    f.ai_report_time = '08:00'
    f.ai_report_days = [1, 2, 3, 4, 5, 6, 0]
  }
  refreshAIKeyStatus()
  loadConsolePort()
}

// parseReportCron 把日报 cron（分 时 * * dow）解析回时间与星期多选；
// 支持全选 *、区间（1-5）、逗号列表与单日；解析失败返回 null（保留表单默认值）。
function parseReportCron(expr) {
  const parts = String(expr || '').trim().split(/\s+/)
  if (parts.length !== 5 || parts[2] !== '*' || parts[3] !== '*') return null
  const m = Number(parts[0]), h = Number(parts[1])
  if (!Number.isInteger(m) || m < 0 || m > 59 || !Number.isInteger(h) || h < 0 || h > 23) return null
  const dow = parts[4]
  let days = []
  if (dow === '*') {
    days = [0, 1, 2, 3, 4, 5, 6]
  } else {
    for (const seg of dow.split(',')) {
      const range = seg.match(/^(\d+)-(\d+)$/)
      if (range) {
        const lo = Number(range[1]), hi = Number(range[2])
        if (lo > hi) return null
        for (let d = lo; d <= hi; d++) days.push(d % 7)
      } else if (/^\d+$/.test(seg)) {
        days.push(Number(seg) % 7)
      } else {
        return null
      }
    }
  }
  days = [...new Set(days)].sort((a, b) => a - b)
  if (!days.length) return null
  return { time: `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`, days }
}

// buildReportCron 由时间（HH:mm）与星期多选生成日报 cron；全选输出 *。
function buildReportCron(time, days) {
  const [h, m] = String(time || '08:00').split(':').map(v => Number(v) || 0)
  const ds = [...new Set((days || []).map(Number))].sort((a, b) => a - b)
  const dow = (ds.length === 7 || ds.length === 0) ? '*' : ds.join(',')
  return `${m} ${h} * * ${dow}`
}

const templates = [
  { id: 'openai', name: 'OpenAI' }, { id: 'deepseek', name: 'DeepSeek' },
  { id: 'qwen', name: '通义千问' }, { id: 'zhipu', name: '智谱' },
  { id: 'moonshot', name: 'Kimi' }, { id: 'doubao', name: '豆包' },
  { id: 'openrouter', name: 'OpenRouter' }, { id: 'ollama', name: 'Ollama' },
  { id: 'vllm', name: 'vLLM' }, { id: 'custom', name: '自定义' }
]
function onTemplate(id) {
  const hints = { openai: 'https://api.openai.com/v1', deepseek: 'https://api.deepseek.com/v1',
    qwen: 'https://dashscope.aliyuncs.com/compatible-mode/v1', zhipu: 'https://open.bigmodel.cn/api/paas/v4',
    moonshot: 'https://api.moonshot.cn/v1', openrouter: 'https://openrouter.ai/api/v1' }
  if (hints[id]) f.ai_base = hints[id]
}

async function testShip() {
  testing.value = true
  testResult.value = null
  try {
    testResult.value = await post('/api/logship/test')
  } catch (e) {
    testResult.value = { ok: false, detail: e.message }
  } finally {
    testing.value = false
  }
}



async function save() {
  // AI 日报表单校验（整页单保存按钮，与其它节无关）
  if (f.ai_enabled && f.ai_analysis) {
    if (!f.ai_report_time) return ElMessage.warning('请选择 AI 日报执行时间')
    if (!f.ai_report_days.length) return ElMessage.warning('AI 日报请至少选择一个重复日')
    const wan = Number(f.ai_report_tokens_wan)
    if (!Number.isFinite(wan) || wan < 1 || wan > 1000) return ElMessage.warning('单日 Token 限额需在 1–1000 万之间')
  }
  const d = await api('/api/config')
  const cfg = d.config
  cfg.capture_requests = f.capture_requests
  // 匿名安装统计：缺省键 = 关闭（与后端语义一致）
  if (f.telemetry_enabled) cfg.telemetry = { enabled: true }
  else delete cfg.telemetry
  cfg.audit_retention_days = f.audit_retention_days
  cfg.audit_archive = { ...(cfg.audit_archive || {}), retention_days: f.archive_retention_days, enabled: cfg.audit_archive?.enabled !== false }
  if (f.query_degraded) cfg.audit_query = { ...(cfg.audit_query || {}), degraded: true }
  else delete cfg.audit_query
  if (f.metrics_enabled) {
    cfg.metrics = { enabled: true }
    if (f.metrics_push_url) {
      let pu = f.metrics_push_url.trim()
      if (!/^https?:\/\//i.test(pu)) pu = 'https://' + pu
      cfg.metrics.push = { url: pu, interval_sec: f.metrics_push_interval || 30, bearer_token: f.metrics_push_token || undefined }
    }
  } else {
    delete cfg.metrics
  }
  if (f.api_assets_enabled) cfg.api_assets = { ...(cfg.api_assets || {}), enabled: true }
  else delete cfg.api_assets
  if (f.risks_enabled) cfg.risks = { ...(cfg.risks || {}), enabled: true }
  else delete cfg.risks
  if (f.shipper_enabled) {
    cfg.log_shipper = { type: f.shipper_type, url: f.shipper_url, index: f.shipper_index }
    if (['clickhouse', 'elasticsearch', 'loki'].includes(f.shipper_type)) {
      if (f.shipper_user) cfg.log_shipper.username = f.shipper_user
      if (f.shipper_pass) cfg.log_shipper.password = f.shipper_pass
    }
    if (f.shipper_type === 's3') {
      cfg.log_shipper = { type: 's3', index: f.shipper_index, endpoint: f.s3_endpoint, bucket: f.s3_bucket, prefix: f.s3_prefix, access_key: f.s3_ak, secret_key: f.s3_sk, use_ssl: f.s3_ssl }
    }
    if (f.shipper_type === 'kafka') {
      const brokers = String(f.shipper_kafka_brokers || '').split(/[\n,]+/).map(s => s.trim()).filter(Boolean)
      cfg.log_shipper = { type: 'kafka', index: f.shipper_index, brokers, topic: f.shipper_kafka_topic, use_tls: f.shipper_kafka_tls, sasl: f.shipper_kafka_sasl }
      if (f.shipper_kafka_tls && !f.shipper_kafka_tls_skip) cfg.log_shipper.tls_skip_verify = false
      if (f.shipper_kafka_sasl !== 'none') {
        if (f.shipper_user) cfg.log_shipper.username = f.shipper_user
        if (f.shipper_pass) cfg.log_shipper.password = f.shipper_pass
      }
    }
  } else delete cfg.log_shipper
  if (f.access_enabled) {
    cfg.access_log = { enabled: true, type: f.access_type, url: f.access_url, index: f.access_index, sample_pct: f.access_sample }
    if (['clickhouse', 'elasticsearch', 'loki'].includes(f.access_type)) {
      if (f.access_user) cfg.access_log.username = f.access_user
      if (f.access_pass) cfg.access_log.password = f.access_pass
    }
    if (f.access_type === 's3') {
      cfg.access_log = { enabled: true, type: 's3', index: f.access_index, sample_pct: f.access_sample,
        endpoint: f.access_s3_endpoint, bucket: f.access_s3_bucket, prefix: f.access_s3_prefix, access_key: f.access_s3_ak, secret_key: f.access_s3_sk, use_ssl: f.access_s3_ssl }
    }
  } else delete cfg.access_log
  // webhook 通知渠道在「告警与通知」Tab 配置（含加签/关键词字段）
  if (f.webhook_url) {
    cfg.webhook = { ...(cfg.webhook || {}), url: f.webhook_url }
    if (f.webhook_secret) cfg.webhook.secret = f.webhook_secret
    if (f.webhook_keyword) cfg.webhook.keyword = f.webhook_keyword
  } else if (cfg.alerts && (f.alerts_webhook || f.alerts_email)) {
    delete cfg.webhook
  }
  // 告警引擎 + 阈值
  if (f.alerts_enabled) {
    cfg.alerts = {
      enabled: true,
      interval_sec: f.alerts_interval,
      cooldown_min: f.alerts_cooldown,
      notify_webhook: f.alerts_webhook,
      notify_email: f.alerts_email,
      rules: {
        cpu: { enabled: f.alert_rules.cpu.enabled, threshold: f.alert_rules.cpu.threshold, window_sec: f.alert_rules.cpu.window_sec || 60 },
        mem: { enabled: f.alert_rules.mem.enabled, threshold: f.alert_rules.mem.threshold, window_sec: f.alert_rules.mem.window_sec || 60 },
        disk: { enabled: f.alert_rules.disk.enabled, threshold: f.alert_rules.disk.threshold },
        web_requests: { enabled: f.alert_rules.requests.enabled, threshold: f.alert_rules.requests.threshold },
        web_attacks: { enabled: f.alert_rules.attacks.enabled, threshold: f.alert_rules.attacks.threshold },
        blocked: { enabled: f.alert_rules.blocked.enabled, threshold: f.alert_rules.blocked.threshold },
        top_attack_ip: { enabled: f.alert_rules.top_ip.enabled, threshold: f.alert_rules.top_ip.threshold },
        top_target: { enabled: f.alert_rules.top_target.enabled, threshold: f.alert_rules.top_target.threshold },
      },
    }
  } else delete cfg.alerts
  // 邮件通道(SMTP)
  if (f.email_enabled && f.email_host && f.email_from) {
    cfg.email = {
      enabled: true, host: f.email_host, port: f.email_port, from: f.email_from,
      username: f.email_user, password: f.email_pass, ssl: f.email_ssl,
      to: f.email_to.filter(Boolean),
    }
  } else if (cfg.email && !f.email_enabled) {
    cfg.email = { ...(cfg.email || {}), enabled: false }
  }
  // 安全设置(密码策略/会话超时/登录锁定/密码历史)
  cfg.security = {
    password_min_len: f.sec_min_len,
    password_complexity: f.sec_complexity,
    password_max_age_days: f.sec_max_age,
    session_timeout_min: f.sec_session,
    password_history_count: f.sec_pw_history,
    login_max_failures: f.sec_login_max,
    login_lockout_min: f.sec_lockout_min,
  }
  if (f.console_ips.filter(Boolean).length) {
    cfg.console = { allowed_ips: f.console_ips.filter(Boolean) }
  } else delete cfg.console
  // 管理面 IP 白名单由「用户管理 → 安全设置」维护，此处不再触碰 cfg.console
  // 拦截页定制（block_page）：四项全空则整体删除，回落内置拦截页
  if (f.bp_title || f.bp_message || f.bp_footer || f.bp_html) {
    cfg.block_page = { title: f.bp_title, message: f.bp_message, footer: f.bp_footer }
    if (f.bp_html) cfg.block_page.html = f.bp_html
  } else delete cfg.block_page
  if (f.ai_enabled) {
    // 从加载的 c.ai 展开/合并：透传保留 api_key_hash/api_key_cipher 等
    // 表单不回显的字段，否则本次发布会把已存库的 Key 字段丢掉
    cfg.ai = {
      ...(cfg.ai || {}),
      enabled: true,
      provider: {
        ...(cfg.ai?.provider || {}),
        template: f.ai_template, base_url: f.ai_base, model: f.ai_model,
        max_tokens: f.ai_max_tokens, temperature: Number(f.ai_temperature) || 0.2, timeout_sec: f.ai_timeout,
      },
      chat: { context_window_tokens: f.ai_ctx_tokens || undefined, keep_recent_turns: f.ai_keep_turns, history_retention_days: f.ai_history_days || undefined },
      sanitize: { ...(cfg.ai?.sanitize || {}), enabled: !!f.ai_sanitize },
      analysis: { ...(cfg.ai?.analysis || {}), enabled: !!f.ai_analysis, max_tokens_per_day: Math.round(Number(f.ai_report_tokens_wan) * 10000) },
    }
    if (f.ai_analysis) {
      // 只重建 attack_summary_daily 条目，其它 kind 的既有计划保留不动
      const daily = { kind: 'attack_summary_daily', cron: buildReportCron(f.ai_report_time, f.ai_report_days), channel: f.ai_report_channel }
      if (f.ai_report_channel === 'webhook') daily.webhook = (f.ai_report_webhook || '').trim()
      else daily.email = (f.ai_report_email || '').trim()
      const others = (cfg.ai.analysis.schedules || []).filter(s => s.kind !== 'attack_summary_daily')
      cfg.ai.analysis.schedules = [...others, daily]
    }
    if (f.ai_sysprompt) cfg.ai.system_prompt = f.ai_sysprompt
  } else if (typeof cfg.ai === 'object') {
    cfg.ai = { ...(cfg.ai || {}), enabled: false }
  }
  const sysPayload = (fmt, host) => {
    const s = { format: fmt }
    if (host) s.hostname = host
    return s
  }
  if (f.shipper_enabled && f.shipper_type === 'syslog') {
    cfg.log_shipper = { type: 'syslog', url: f.shipper_url, index: f.shipper_index, syslog: sysPayload(f.shipper_sys_format, f.shipper_sys_hostname) }
  }
  if (f.access_enabled && f.access_type === 'syslog') {
    cfg.access_log = { enabled: true, type: 'syslog', url: f.access_url, index: f.access_index, sample_pct: f.access_sample, syslog: sysPayload(f.access_sys_format, f.access_sys_hostname) }
  }
  try {
    const r = await post('/api/config/publish', { note: 'settings update', config: cfg })
    ElMessage.success('已发布并热生效（版本 ' + r.revision + '）')
    load()
  } catch (e) {
    ElMessage.error('发布失败：' + e.message)
  }
}

onMounted(load)
onBeforeUnmount(() => { if (portCountdown) clearInterval(portCountdown) })
</script>

<style scoped>
</style>
