{{/* Names */}}
{{- define "mgw.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mgw.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "mgw.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "mgw.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: mcp-gateway
{{- end -}}

{{/* Selector labels for one component: include "mgw.selector" (list . "api") */}}
{{- define "mgw.selector" -}}
{{- $ctx := index . 0 -}}
app.kubernetes.io/name: {{ include "mgw.name" $ctx }}
app.kubernetes.io/instance: {{ $ctx.Release.Name }}
app.kubernetes.io/component: {{ index . 1 }}
{{- end -}}

{{- define "mgw.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "mgw.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "mgw.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "mgw.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Image reference: include "mgw.image" (list . .Values.image.backend) */}}
{{- define "mgw.image" -}}
{{- $ctx := index . 0 -}}
{{- $img := index . 1 -}}
{{- $tag := $img.tag | default $ctx.Chart.AppVersion | toString -}}
{{- if $ctx.Values.global.imageRegistry -}}
{{- printf "%s/%s:%s" (trimSuffix "/" $ctx.Values.global.imageRegistry) $img.repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $img.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "mgw.publicBaseUrl" -}}
{{- if .Values.publicBaseUrl -}}
{{- .Values.publicBaseUrl | trimSuffix "/" -}}
{{- else if .Values.ingress.enabled -}}
{{- printf "%s://%s" (ternary "https" "http" .Values.ingress.tls.enabled) .Values.ingress.host -}}
{{- else -}}
{{- fail "Set publicBaseUrl (the URL users and agents use), or enable the ingress." -}}
{{- end -}}
{{- end -}}

{{/* Restricted Pod Security Standard: include "mgw.podSecurity" (list uid gid) */}}
{{- define "mgw.podSecurity" -}}
runAsNonRoot: true
runAsUser: {{ index . 0 }}
runAsGroup: {{ index . 1 }}
fsGroup: {{ index . 1 }}
seccompProfile: { type: RuntimeDefault }
{{- end -}}

{{/* Spread replicas over nodes unless the user configured affinity: include "mgw.affinity" (list . "api" .Values.api.affinity) */}}
{{- define "mgw.affinity" -}}
{{- $ctx := index . 0 -}}
{{- $affinity := index . 2 -}}
{{- if $affinity }}
affinity: {{- toYaml $affinity | nindent 2 }}
{{- else }}
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          topologyKey: kubernetes.io/hostname
          labelSelector:
            matchLabels: {{- include "mgw.selector" (list $ctx (index . 1)) | nindent 14 }}
{{- end }}
{{- end -}}

{{- define "mgw.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: { drop: [ALL] }
{{- end -}}

{{- define "mgw.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* Environment shared by the API and the worker. Secrets are mounted as files and read through *_FILE. */}}
{{- define "mgw.backendEnv" -}}
- name: SESSION_SECRET_FILE
  value: /run/secrets/mgw/session_secret
- name: DATA_ENCRYPTION_KEY_FILE
  value: /run/secrets/mgw/data_encryption_key
- name: API_KEY_HASH_PEPPER_FILE
  value: /run/secrets/mgw/api_key_hash_pepper
- name: BOOTSTRAP_ADMIN_PASSWORD_FILE
  value: /run/secrets/mgw/bootstrap_admin_password
- name: MONGODB_URI_FILE
  value: /run/secrets/mgw/mongodb_uri
- name: REDIS_URL_FILE
  value: /run/secrets/mgw/redis_url
{{- if .Values.mtls.enabled }}
- name: MTLS_CLIENT_CA_FILE
  value: /run/secrets/mgw-mtls/agent-ca.pem
- name: MTLS_TRUSTED_PROXIES
  value: {{ .Values.mtls.trustedProxies | quote }}
{{- end }}
{{- end -}}

{{- define "mgw.backendVolumes" -}}
- name: secrets
  secret:
    secretName: {{ include "mgw.secretName" . }}
    defaultMode: 0440
    items:
      {{- range list "session_secret" "data_encryption_key" "api_key_hash_pepper" "bootstrap_admin_password" "mongodb_uri" "redis_url" }}
      - { key: {{ . }}, path: {{ . }} }
      {{- end }}
- name: tmp
  emptyDir: { medium: Memory, sizeLimit: 64Mi }
{{- if .Values.mtls.enabled }}
- name: mtls-ca
  secret:
    secretName: {{ .Values.mtls.existingSecret }}
    defaultMode: 0440
    items: [{ key: agent-ca.pem, path: agent-ca.pem }]
{{- end }}
{{- end -}}

{{- define "mgw.backendMounts" -}}
- { name: secrets, mountPath: /run/secrets/mgw, readOnly: true }
- { name: tmp, mountPath: /tmp }
{{- if .Values.mtls.enabled }}
- { name: mtls-ca, mountPath: /run/secrets/mgw-mtls, readOnly: true }
{{- end }}
{{- end -}}

{{/* Checks that run on every render. */}}
{{- define "mgw.validate" -}}
{{- if and (not .Values.secrets.existingSecret) (not .Values.secrets.generate) -}}
{{- fail "Set secrets.existingSecret (recommended; see deploy/helm/create-secret.sh) or secrets.generate=true." -}}
{{- end -}}
{{- if .Values.mtls.enabled -}}
{{- if not .Values.mtls.existingSecret -}}{{- fail "mtls.existingSecret is required with mtls.enabled" -}}{{- end -}}
{{- if not .Values.mtls.trustedProxies -}}{{- fail "mtls.trustedProxies is required with mtls.enabled (the web UI pods' address range)" -}}{{- end -}}
{{- if not .Values.networkPolicy.enabled -}}{{- fail "mtls.enabled needs networkPolicy.enabled: without it, any pod in trustedProxies could forge a client certificate header" -}}{{- end -}}
{{- end -}}
{{- if and .Values.secrets.generate (not .Values.mongodb.enabled) -}}
{{- fail "secrets.generate builds mongodb_uri for the bundled MongoDB only; with an external database use secrets.existingSecret" -}}
{{- end -}}
{{- if and .Values.secrets.generate (not .Values.redis.enabled) -}}
{{- fail "secrets.generate builds redis_url for the bundled Redis only; with an external Redis use secrets.existingSecret" -}}
{{- end -}}
{{- end -}}
